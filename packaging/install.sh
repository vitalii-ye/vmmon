#!/bin/sh
# Install vmmon from a GitHub release: curl -fsSL <this script> | sh
#
# Verifies the tarball's sha256 before installing anything, installs the binary
# and the systemd unit, and never starts the service: `sudo vmmon setup` does that.
#
# Environment:
#   VMMON_VERSION      release to install, e.g. 1.2.3 or v1.2.3 (default: latest)
#   VMMON_PREFIX       install under this directory instead of /, without root
#                      or systemctl (for tests and packaging)
#   VMMON_RELEASE_URL  base URL instead of the GitHub releases page (for tests)
#
# All of it is inside main, called on the last line, so that a truncated download
# defines at most part of a function and runs nothing.

main() {
	set -eu
	umask 022

	repo_url="https://github.com/vitalii-ye/vmmon/releases"
	release_url="${VMMON_RELEASE_URL:-$repo_url}"
	prefix="${VMMON_PREFIX:-}"
	bin_dir="$prefix/usr/local/bin"
	unit_dir="$prefix/etc/systemd/system"
	unit_file="vmmon.service"

	# Platform first: it needs no tools and is the most likely refusal.
	os="$(uname -s)"
	[ "$os" = "Linux" ] || die "unsupported OS: $os. vmmon runs on Linux only."
	machine="$(uname -m)"
	case "$machine" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) die "unsupported architecture: $machine. vmmon releases cover amd64 and arm64." ;;
	esac

	sudo_cmd=""
	if [ -z "$prefix" ] && [ "$(id -u)" -ne 0 ]; then
		command -v sudo >/dev/null 2>&1 || die "installing needs root, and sudo was not found. Run this as root."
		sudo_cmd="sudo"
	fi

	check_distro "$prefix/etc/os-release" "$prefix/usr/lib/os-release"

	for tool in curl tar mktemp install mv awk sed tr rm; do
		command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
	done
	if command -v sha256sum >/dev/null 2>&1; then
		sha_cmd="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		sha_cmd="shasum -a 256"
	else
		die "cannot verify the download: neither sha256sum nor shasum was found"
	fi

	if [ -z "$prefix" ] && command -v dpkg-query >/dev/null 2>&1 &&
		[ "$(dpkg-query -W -f='${Status}' vmmon 2>/dev/null || true)" = "install ok installed" ]; then
		die "vmmon is installed from the .deb package, which owns these files. Upgrade with the newer .deb instead."
	fi

	case "${VMMON_VERSION:-}" in
	"") base="$release_url/latest/download" ;;
	*[!A-Za-z0-9._-]* | -*) die "invalid VMMON_VERSION: $VMMON_VERSION" ;;
	v*) base="$release_url/download/$VMMON_VERSION" ;;
	*) base="$release_url/download/v$VMMON_VERSION" ;;
	esac

	tarball="vmmon_linux_$arch.tar.gz"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	trap 'rm -rf "$tmp"; exit 130' INT
	trap 'rm -rf "$tmp"; exit 143' TERM

	say "Downloading $base/$tarball"
	fetch "$base/$tarball" "$tmp/$tarball" || die "could not download $tarball"
	fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt"

	expected="$(awk -v file="$tarball" '$2 == file || $2 == "*" file { print $1; exit }' "$tmp/checksums.txt" | tr 'A-F' 'a-f')"
	case "$expected" in
	"") die "checksums.txt has no entry for $tarball; nothing was installed" ;;
	*[!0-9a-f]*) die "checksums.txt has a malformed entry for $tarball; nothing was installed" ;;
	esac
	[ "${#expected}" -eq 64 ] || die "checksums.txt has a malformed entry for $tarball; nothing was installed"
	# $sha_cmd is unquoted on purpose: "shasum -a 256" is a command and arguments.
	# shellcheck disable=SC2086
	actual="$($sha_cmd "$tmp/$tarball" | awk '{ print $1 }')"
	[ "$actual" = "$expected" ] || die "checksum mismatch for $tarball; nothing was installed
  expected $expected
  actual   $actual"
	say "Checksum verified."

	tar -xzf "$tmp/$tarball" -C "$tmp" vmmon "$unit_file" || die "$tarball lacks the binary or the unit; nothing was installed"
	# Checked up front, so a malformed release cannot install half of itself.
	if [ ! -f "$tmp/vmmon" ] || [ ! -f "$tmp/$unit_file" ]; then
		die "$tarball lacks the binary or the unit; nothing was installed"
	fi

	# Staged beside the target and renamed, so a running binary or a failed copy
	# never leaves a partial file at the real path.
	$sudo_cmd install -d -m 0755 "$bin_dir" "$unit_dir"
	$sudo_cmd install -m 0755 "$tmp/vmmon" "$bin_dir/.vmmon.new"
	$sudo_cmd mv -f "$bin_dir/.vmmon.new" "$bin_dir/vmmon"
	$sudo_cmd install -m 0644 "$tmp/$unit_file" "$unit_dir/.$unit_file.new"
	$sudo_cmd mv -f "$unit_dir/.$unit_file.new" "$unit_dir/$unit_file"
	say "Installed $bin_dir/vmmon and $unit_dir/$unit_file"

	if [ -n "$prefix" ]; then
		say "VMMON_PREFIX is set, so systemd was left alone."
	elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		$sudo_cmd systemctl daemon-reload
		# Upgrades only: try-restart does nothing unless the service is running.
		$sudo_cmd systemctl try-restart "$unit_file"
	else
		say "systemd is not running here, so no service was registered."
	fi

	say ""
	say "Next step, to pair Telegram and start the service:"
	say ""
	say "  sudo vmmon setup"
}

say() {
	printf '%s\n' "$1"
}

die() {
	printf 'vmmon install: %s\n' "$1" >&2
	exit 1
}

fetch() {
	if [ -n "${VMMON_RELEASE_URL:-}" ]; then
		curl -fsSL -o "$2" "$1"
	else
		curl --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -fsSL -o "$2" "$1"
	fi
}

# The first file that exists decides, as in os-release(5).
check_distro() {
	release_file=""
	for candidate in "$@"; do
		if [ -r "$candidate" ]; then
			release_file="$candidate"
			break
		fi
	done
	[ -n "$release_file" ] || die "cannot identify this system: no os-release file. vmmon supports Debian 12, 13 and Ubuntu 22.04, 24.04."
	distro="$(os_release_value ID "$release_file")"
	distro_version="$(os_release_value VERSION_ID "$release_file")"
	case "$distro:$distro_version" in
	debian:12 | debian:13 | ubuntu:22.04 | ubuntu:24.04) ;;
	*) die "unsupported system: $distro $distro_version. vmmon supports Debian 12, 13 and Ubuntu 22.04, 24.04." ;;
	esac
}

os_release_value() {
	sed -n "s/^$1=//p" "$2" | tr -d "\"'"
}

main "$@"
