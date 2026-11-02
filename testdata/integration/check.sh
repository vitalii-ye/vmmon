#!/bin/sh
# Asserts on what the binary printed: version.txt, inventory.json and scan.json in
# DIR. Needs jq. Usage: check.sh DIR ECOSYSTEM [ARCH]
# $eco in the filters is a jq variable, so single quotes are right.
# shellcheck disable=SC2016
set -eu

dir="$1"
ecosystem="$2"
arch="${3:-amd64}"

die() {
	printf 'check failed (%s): %s\n' "$ecosystem" "$1" >&2
	exit 1
}

# assert FILE JQ_FILTER: the filter must evaluate to true.
assert() {
	jq -e --arg eco "$ecosystem" "$2" "$dir/$1" >/dev/null || die "$1: $2"
}

grep -Eq "^vmmon .*linux/$arch\)$" "$dir/version.txt" || die "version.txt: $(cat "$dir/version.txt")"

assert inventory.json '.release.ecosystem == $eco'
assert inventory.json '.hostname | length > 0'
assert inventory.json '.packages | length > 0'
assert inventory.json 'any(.packages[]; .name == "bash" and .source_name == "bash" and .source_version == .version)'
# The source mapping OSV matching depends on.
assert inventory.json 'any(.packages[]; .name == "libc6" and .source_name == "glibc")'

assert scan.json '.ecosystem == $eco'
assert scan.json '.packages_count > 0'
assert scan.json '.db_synced_at != null'
assert scan.json '.counts == {total: 3, kev: 1, fix_available: 2, no_fix_yet: 1}'
assert scan.json '[.findings[].vuln_id] | sort == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]'
assert scan.json 'all(.findings[]; .ecosystem == $eco)'
assert scan.json 'any(.findings[]; .vuln_id == "CVE-2099-0001" and .source_package == "bash" and .fix_status == "fix-available" and .fixed_version == "999:1-1" and .epss == 0.5 and .kev == false)'
assert scan.json 'any(.findings[]; .vuln_id == "CVE-2099-0002" and .source_package == "coreutils" and .fix_status == "no-fix-yet" and .kev == true)'
assert scan.json 'any(.findings[]; .vuln_id == "CVE-2099-0003" and .source_package == "glibc" and (.binary_packages | index("libc6") != null))'
# A fresh fixture with both feeds synced has nothing to warn about.
assert scan.json '(.warnings // []) | length == 0'

printf 'ok: %s\n' "$ecosystem"
