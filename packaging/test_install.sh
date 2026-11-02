#!/bin/sh
# Tests install.sh against a local fake release, without root or network. Anything
# real it would need (uname, the install location) comes from stubs and VMMON_PREFIX.
# Usage: sh packaging/test_install.sh. TEST_SHELL=dash runs install.sh under dash.
# Here pass and fail always succeed, so "A && pass || fail" is a safe if-then-else.
# shellcheck disable=SC2015,SC2012
set -u

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/install.sh"
shell="$(command -v "${TEST_SHELL:-sh}")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
passes=0

pass() {
	passes=$((passes + 1))
	printf 'ok    %s\n' "$1"
}

fail() {
	failures=$((failures + 1))
	printf 'FAIL  %s\n' "$1"
	[ -f "$work/out" ] && sed 's/^/      /' "$work/out"
}

sha_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

# make_release DIR MARKER: a release whose binary prints MARKER.
make_release() {
	mkdir -p "$1"
	for a in amd64 arm64; do
		pkg="$work/pkg-$a"
		rm -rf "$pkg"
		mkdir -p "$pkg"
		printf '#!/bin/sh\necho "%s %s"\n' "$2" "$a" >"$pkg/vmmon"
		chmod 755 "$pkg/vmmon"
		printf '[Service]\nExecStart=/usr/local/bin/vmmon daemon\n' >"$pkg/vmmon.service"
		echo license >"$pkg/LICENSE"
		tar -czf "$1/vmmon_linux_$a.tar.gz" -C "$pkg" vmmon vmmon.service LICENSE
		printf '%s  vmmon_linux_%s.tar.gz\n' "$(sha_of "$1/vmmon_linux_$a.tar.gz")" "$a" >>"$1/checksums.txt"
	done
}

release="$work/release"
make_release "$release/latest/download" latest
make_release "$release/download/v1.2.3" pinned

# uname answers from the environment; curl logs that it ran, then does its job.
stubs="$work/stubs"
mkdir -p "$stubs"
real_curl="$(command -v curl)"
cat >"$stubs/uname" <<'STUB'
#!/bin/sh
case "$1" in
-s) echo "$FAKE_OS" ;;
-m) echo "$FAKE_ARCH" ;;
esac
STUB
cat >"$stubs/curl" <<STUB
#!/bin/sh
echo "\$*" >>"$work/curl.log"
exec "$real_curl" "\$@"
STUB
chmod 755 "$stubs/uname" "$stubs/curl"

# new_root [DISTRO [VERSION]]: an empty install root with an os-release file.
new_root() {
	root="$(mktemp -d "$work/root.XXXXXX")"
	mkdir -p "$root/etc"
	printf 'PRETTY_NAME="x"\nID=%s\nVERSION_ID="%s"\n' "${1:-debian}" "${2:-12}" >"$root/etc/os-release"
	: >"$work/curl.log"
}

# run ROOT [VAR=value...]: run install.sh; output goes to $work/out.
run() {
	run_root="$1"
	shift
	env PATH="$stubs:$PATH" FAKE_OS=Linux FAKE_ARCH=x86_64 \
		VMMON_PREFIX="$run_root" VMMON_RELEASE_URL="file://$release" "$@" \
		"$shell" "$script" >"$work/out" 2>&1
}

nothing_installed() {
	[ ! -e "$1/usr/local/bin" ] && [ ! -e "$1/etc/systemd" ]
}

# Good checksum, default version and architecture.
new_root
if run "$root" && [ "$("$root/usr/local/bin/vmmon")" = "latest amd64" ] &&
	[ -f "$root/etc/systemd/system/vmmon.service" ]; then
	pass "good checksum installs the binary and unit"
else
	fail "good checksum installs the binary and unit"
fi
grep -q 'sudo vmmon setup' "$work/out" && pass "prints sudo vmmon setup" || fail "prints sudo vmmon setup"
mode="$(ls -l "$root/usr/local/bin/vmmon" | cut -c1-10)"
[ "$mode" = "-rwxr-xr-x" ] && pass "binary is 0755" || fail "binary is 0755, got $mode"
mode="$(ls -l "$root/etc/systemd/system/vmmon.service" | cut -c1-10)"
[ "$mode" = "-rw-r--r--" ] && pass "unit is 0644" || fail "unit is 0644, got $mode"
leftovers="$(find "$root" -name '.*new' | wc -l | tr -d ' ')"
[ "$leftovers" = "0" ] && pass "leaves no staged files" || fail "leaves no staged files"

# Idempotent.
if run "$root" && [ "$("$root/usr/local/bin/vmmon")" = "latest amd64" ]; then
	pass "running twice succeeds"
else
	fail "running twice succeeds"
fi

# Architecture mapping.
for machine in aarch64 arm64; do
	new_root
	if run "$root" FAKE_ARCH="$machine" && [ "$("$root/usr/local/bin/vmmon")" = "latest arm64" ]; then
		pass "$machine selects the arm64 tarball"
	else
		fail "$machine selects the arm64 tarball"
	fi
done

# Every supported release, including os-release only under /usr/lib.
for pair in debian:13 ubuntu:22.04 ubuntu:24.04; do
	new_root "${pair%%:*}" "${pair#*:}"
	run "$root" && pass "accepts $pair" || fail "accepts $pair"
done
new_root debian 13
mkdir -p "$root/usr/lib"
mv "$root/etc/os-release" "$root/usr/lib/os-release"
run "$root" && pass "falls back to /usr/lib/os-release" || fail "falls back to /usr/lib/os-release"

# VMMON_VERSION, with and without the v.
for v in 1.2.3 v1.2.3; do
	new_root
	if run "$root" VMMON_VERSION="$v" && [ "$("$root/usr/local/bin/vmmon")" = "pinned amd64" ]; then
		pass "VMMON_VERSION=$v selects that release"
	else
		fail "VMMON_VERSION=$v selects that release"
	fi
done
new_root
if ! run "$root" VMMON_VERSION=9.9.9 && nothing_installed "$root"; then
	pass "a missing release fails"
else
	fail "a missing release fails"
fi
new_root
if ! run "$root" VMMON_VERSION=../../evil && nothing_installed "$root" && [ ! -s "$work/curl.log" ]; then
	pass "an unsafe VMMON_VERSION is refused before any download"
else
	fail "an unsafe VMMON_VERSION is refused before any download"
fi

# Bad checksums, each against a copy of the release. Each must fail for its own
# reason: a test failing at some earlier step would otherwise pass for nothing.
tampered_count=0
tampered() { # NAME EXPECTED_MESSAGE EDIT_COMMAND
	tampered_count=$((tampered_count + 1))
	bad="$work/bad-$tampered_count"
	mkdir -p "$bad"
	cp -R "$release/latest" "$bad/latest"
	(cd "$bad/latest/download" && eval "$3")
	new_root
	if ! run "$root" VMMON_RELEASE_URL="file://$bad" && grep -q "$2" "$work/out" && nothing_installed "$root"; then
		pass "$1 installs nothing"
	else
		fail "$1 installs nothing"
	fi
}
tampered "tampered tarball" "checksum mismatch" 'echo x >>vmmon_linux_amd64.tar.gz'
tampered "wrong checksum" "checksum mismatch" 'sed "s/^.\{64\}/0000000000000000000000000000000000000000000000000000000000000000/" checksums.txt >c && mv c checksums.txt'
tampered "missing checksums.txt" "could not download checksums.txt" 'rm checksums.txt'
tampered "no entry for the tarball" "no entry for" 'grep -v amd64 checksums.txt >c; mv c checksums.txt'
tampered "empty checksums.txt" "no entry for" ': >checksums.txt'
tampered "short checksum" "malformed entry" 'sed "s/^.\{64\}/abcd/" checksums.txt >c && mv c checksums.txt'
tampered "non-hex checksum" "malformed entry" 'sed "s/^.\{64\}/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/" checksums.txt >c && mv c checksums.txt'
tampered "missing tarball" "could not download vmmon_linux_amd64" 'rm vmmon_linux_amd64.tar.gz'
# Correctly checksummed, but malformed: the unit is missing, or nested in a directory.
reseal() { # the release's amd64 tarball, rebuilt from the current directory's "pkg"
	tar -czf vmmon_linux_amd64.tar.gz -C pkg . &&
		printf '%s  vmmon_linux_amd64.tar.gz\n' "$(sha_of vmmon_linux_amd64.tar.gz)" >checksums.txt
}
tampered "a tarball with no unit" "lacks the binary or the unit" 'mkdir pkg && echo x >pkg/vmmon && reseal'
tampered "a tarball with a nested unit" "lacks the binary or the unit" 'mkdir -p pkg/vmmon.service && echo x >pkg/vmmon && echo y >pkg/vmmon.service/vmmon.service && reseal'

# A bad upgrade leaves the installed version alone.
bad="$work/bad-upgrade"
mkdir -p "$bad"
cp -R "$release/latest" "$bad/latest"
echo x >>"$bad/latest/download/vmmon_linux_amd64.tar.gz"
new_root
run "$root"
before="$(sha_of "$root/usr/local/bin/vmmon")"
if ! run "$root" VMMON_RELEASE_URL="file://$bad" && [ "$(sha_of "$root/usr/local/bin/vmmon")" = "$before" ]; then
	pass "bad checksum keeps the installed binary"
else
	fail "bad checksum keeps the installed binary"
fi
grep -q 'checksum mismatch' "$work/out" && pass "says checksum mismatch" || fail "says checksum mismatch"

# Unsupported platforms: refused clearly, before any download.
refused() { # NAME EXPECTED_MESSAGE ROOT VAR=value...
	name="$1"
	message="$2"
	shift 2
	refused_root="$1"
	shift
	if ! run "$refused_root" "$@" && grep -q "$message" "$work/out" &&
		nothing_installed "$refused_root" && [ ! -s "$work/curl.log" ]; then
		pass "$name is refused"
	else
		fail "$name is refused"
	fi
}
new_root
refused "architecture riscv64" "unsupported architecture: riscv64" "$root" FAKE_ARCH=riscv64
new_root
refused "architecture armv7l" "unsupported architecture: armv7l" "$root" FAKE_ARCH=armv7l
new_root
refused "OS Darwin" "unsupported OS: Darwin" "$root" FAKE_OS=Darwin FAKE_ARCH=arm64
new_root fedora 40
refused "fedora 40" "unsupported system: fedora 40" "$root"
new_root debian 11
refused "debian 11" "unsupported system: debian 11" "$root"
new_root ubuntu 23.10
refused "ubuntu 23.10" "unsupported system: ubuntu 23.10" "$root"
new_root
rm "$root/etc/os-release"
refused "a host with no os-release" "no os-release file" "$root"

# Missing tools fail closed. PATH holds only what is linked here.
minimal_path() { # DIR TOOL...
	dir="$1"
	shift
	rm -rf "$dir"
	mkdir -p "$dir"
	cp "$stubs/uname" "$dir/uname"
	for t in "$@"; do
		target="$(command -v "$t")" && ln -s "$target" "$dir/$t"
	done
}
base_tools="curl tar gzip mktemp install mv awk sed tr rm id cp chmod"
run_minimal() {
	new_root
	env PATH="$work/min" FAKE_OS=Linux FAKE_ARCH=x86_64 \
		VMMON_PREFIX="$root" VMMON_RELEASE_URL="file://$release" \
		"$shell" "$script" >"$work/out" 2>&1
}
# shellcheck disable=SC2086
minimal_path "$work/min" $base_tools
if ! run_minimal && grep -q 'neither sha256sum nor shasum' "$work/out" && nothing_installed "$root"; then
	pass "no checksum tool fails closed"
else
	fail "no checksum tool fails closed"
fi
for tool in sha256sum shasum; do
	if command -v "$tool" >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		minimal_path "$work/min" $base_tools "$tool"
		if run_minimal && [ -x "$root/usr/local/bin/vmmon" ]; then
			pass "verifies with $tool"
		else
			fail "verifies with $tool"
		fi
	fi
done
# shellcheck disable=SC2086,SC2046
minimal_path "$work/min" $(printf '%s\n' $base_tools | grep -v '^curl$') sha256sum shasum
if ! run_minimal && grep -q 'required tool not found: curl' "$work/out" && nothing_installed "$root"; then
	pass "no curl fails closed"
else
	fail "no curl fails closed"
fi

# Not root, no sudo, no prefix: refused before touching anything.
minimal_path "$work/min" sed tr
printf '#!/bin/sh\necho 1000\n' >"$work/min/id"
chmod 755 "$work/min/id"
if ! env PATH="$work/min" FAKE_OS=Linux FAKE_ARCH=x86_64 "$shell" "$script" >"$work/out" 2>&1 &&
	grep -q 'sudo was not found' "$work/out"; then
	pass "non-root without sudo is refused"
else
	fail "non-root without sudo is refused"
fi

# Truncated downloads run nothing, at every line and at a spread of byte offsets.
size="$(wc -c <"$script" | tr -d ' ')"
lines="$(wc -l <"$script" | tr -d ' ')"
truncation_ran=0
check_truncated() {
	new_root
	PATH="$stubs:$PATH" FAKE_OS=Linux FAKE_ARCH=x86_64 VMMON_PREFIX="$root" VMMON_RELEASE_URL="file://$release" \
		"$shell" "$work/partial.sh" >/dev/null 2>&1
	if ! nothing_installed "$root" || [ -s "$work/curl.log" ]; then
		truncation_ran=$((truncation_ran + 1))
	fi
}
n=1
while [ "$n" -lt "$lines" ]; do
	head -n "$n" "$script" >"$work/partial.sh"
	check_truncated
	n=$((n + 1))
done
offset=7
while [ "$offset" -lt "$((size - 12))" ]; do
	head -c "$offset" "$script" >"$work/partial.sh"
	check_truncated
	offset=$((offset + 97))
done
[ "$truncation_ran" -eq 0 ] && pass "truncated downloads run nothing" ||
	fail "truncated downloads run nothing ($truncation_ran ran)"

# The rule that matters most is not observable without systemd, so read the source.
if grep -nE 'systemctl[^#]*[[:space:]](start|enable|restart|reload-or-restart)([[:space:]]|$)' "$script" >"$work/out"; then
	fail "never starts or enables the service"
else
	pass "never starts or enables the service"
fi

rm -f "$work/out"
printf '\n%d passed, %d failed\n' "$passes" "$failures"
[ "$failures" -eq 0 ]
