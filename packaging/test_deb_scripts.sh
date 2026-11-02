#!/bin/sh
# Tests the .deb maintainer scripts for every dpkg argument that matters. Each
# script is rewritten to use paths under a temp dir, with systemctl stubbed to log.
# Usage: sh packaging/test_deb_scripts.sh
set -u

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
passes=0

mkdir -p "$work/bin"
cat >"$work/bin/systemctl" <<STUB
#!/bin/sh
echo "\$*" >>"$work/calls"
STUB
chmod 755 "$work/bin/systemctl"

# Fake host: systemd running, settings present, data behind a symlink.
reset_host() {
	root="$work/host"
	rm -rf "$root"
	mkdir -p "$root/run/systemd/system" "$root/etc/vmmon" "$root/var/lib/private/vmmon/db" "$root/var/lib/private/other"
	echo token >"$root/etc/vmmon/secrets.env"
	ln -s private/vmmon "$root/var/lib/vmmon"
	: >"$work/calls"
}

# run SCRIPT ARGS...: output goes to $work/out.
run() {
	script="$1"
	shift
	sed -e "s#/run/systemd/system#$root&#g" -e "s#/etc/vmmon#$root&#g" -e "s#/var/lib/#$root&#g" \
		"$here/deb/$script" >"$work/script"
	PATH="$work/bin:$PATH" sh "$work/script" "$@" >"$work/out" 2>&1
}

# expect NAME EXPECTED_CALLS: the systemctl calls made, joined with "; ".
expect() {
	calls="$(paste -s -d ';' "$work/calls" | sed 's/;/; /g')"
	if [ "$calls" = "$2" ]; then
		passes=$((passes + 1))
		printf 'ok    %s\n' "$1"
	else
		failures=$((failures + 1))
		printf 'FAIL  %s: systemctl calls were [%s], want [%s]\n' "$1" "$calls" "$2"
	fi
}

check() { # NAME CONDITION...
	name="$1"
	shift
	if "$@"; then
		passes=$((passes + 1))
		printf 'ok    %s\n' "$name"
	else
		failures=$((failures + 1))
		printf 'FAIL  %s\n' "$name"
	fi
}

data_kept() {
	[ -f "$root/etc/vmmon/secrets.env" ] && [ -d "$root/var/lib/private/vmmon/db" ] && [ -L "$root/var/lib/vmmon" ]
}

data_gone() {
	[ ! -e "$root/etc/vmmon" ] && [ ! -e "$root/var/lib/private/vmmon" ] && [ ! -L "$root/var/lib/vmmon" ] && [ ! -e "$root/var/lib/vmmon" ]
}

reset_host
run postinst configure
expect "fresh install reloads only, never starts" "daemon-reload"
check "fresh install prints the next step" grep -q 'sudo vmmon setup' "$work/out"

reset_host
run postinst configure 1.0.0
expect "upgrade restarts only if running" "daemon-reload; try-restart vmmon.service"
check "upgrade does not repeat the next step" test ! -s "$work/out"

reset_host
run postinst abort-upgrade 1.0.0
expect "abort-upgrade does nothing" ""

reset_host
run prerm remove
expect "remove stops and disables" "stop vmmon.service; disable vmmon.service"

reset_host
run prerm upgrade 2.0.0
expect "upgrade leaves the service running" ""

reset_host
run prerm failed-upgrade 2.0.0
expect "failed-upgrade leaves the service running" ""

reset_host
run postrm remove
expect "remove reloads" "daemon-reload"
check "remove keeps settings and data" data_kept

reset_host
run postrm upgrade 2.0.0
expect "upgrade does not reload in postrm" ""
check "upgrade keeps settings and data" data_kept

reset_host
run postrm purge
expect "purge reloads" "daemon-reload"
check "purge deletes settings and data" data_gone
check "purge leaves other services' private state" test -d "$root/var/lib/private/other"

reset_host
rm "$root/var/lib/vmmon"
mkdir -p "$root/var/lib/vmmon/db"
run postrm purge
check "purge deletes a never-migrated plain state directory" data_gone

reset_host
rm -rf "$root/etc/vmmon" "$root/var/lib/private/vmmon" "$root/var/lib/vmmon"
run postrm purge
check "purge succeeds with nothing to delete" test "$?" -eq 0

# No systemd running, as in a container or chroot: no calls, and no failure.
for call in "postinst configure" "postinst configure 1.0.0" "prerm remove" "postrm remove" "postrm purge"; do
	reset_host
	rmdir "$root/run/systemd/system"
	# shellcheck disable=SC2086
	run $call
	status=$?
	expect "without systemd: $call makes no calls" ""
	check "without systemd: $call succeeds" test "$status" -eq 0
done

printf '\n%d passed, %d failed\n' "$passes" "$failures"
[ "$failures" -eq 0 ]
