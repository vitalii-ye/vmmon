#!/bin/sh
# Runs inside a distro container as root, with no systemd: installs the .deb and
# walks it through remove and purge. Usage: deb.sh PATH_TO_DEB
set -eu

deb="$1"

die() {
	printf 'deb check failed: %s\n' "$1" >&2
	exit 1
}

dpkg -i "$deb" >/tmp/install.log
grep -q 'sudo vmmon setup' /tmp/install.log || die "postinst did not print the next step"
/usr/local/bin/vmmon version | grep -q '^vmmon ' || die "vmmon version"
test -f /usr/lib/systemd/system/vmmon.service || die "unit missing"
test -f /usr/share/doc/vmmon/copyright || die "license missing"
grep -q '^ExecStart=/usr/local/bin/vmmon daemon$' /usr/lib/systemd/system/vmmon.service || die "ExecStart"
dpkg-query -W -f='${Depends}' vmmon | grep -q . && die "the package has hard dependencies"

# Settings and data as setup and the daemon would leave them.
mkdir -p /etc/vmmon /var/lib/private/vmmon/db
echo token >/etc/vmmon/secrets.env
ln -s private/vmmon /var/lib/vmmon

dpkg -r vmmon >/dev/null
test ! -e /usr/local/bin/vmmon || die "binary survived remove"
test ! -e /usr/lib/systemd/system/vmmon.service || die "unit survived remove"
test -f /etc/vmmon/secrets.env || die "remove deleted settings"
test -d /var/lib/private/vmmon/db || die "remove deleted data"

dpkg -P vmmon >/dev/null
test ! -e /etc/vmmon || die "purge left /etc/vmmon"
test ! -e /var/lib/private/vmmon || die "purge left /var/lib/private/vmmon"
test ! -L /var/lib/vmmon || die "purge left the /var/lib/vmmon symlink"

echo "ok: deb install, remove, purge"
