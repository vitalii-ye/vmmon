#!/bin/sh
# Runs the static binary inside a distro container against a fixture DB, with no
# network and as an unprivileged user, as the daemon runs. Asserts with check.sh.
# Usage: run.sh IMAGE ECOSYSTEM BINARY STATE_DIR
# STATE_DIR is $VMMON_IT_STATE from fixture_test.go.
set -eu

image="$1"
ecosystem="$2"
binary="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
state="$(cd "$4" && pwd)/$(printf '%s' "$ecosystem" | tr ':' '_')"
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

chmod -R a+rX "$state"

vmmon() {
	docker run --rm --network none --user 65534:65534 \
		-v "$binary:/usr/local/bin/vmmon:ro" -v "$state:/state:ro" \
		-e VMMON_STATE_DIR=/state \
		"$image" /usr/local/bin/vmmon "$@"
}

vmmon version >"$out/version.txt"
vmmon inventory --json >"$out/inventory.json"
vmmon scan --json >"$out/scan.json"

sh "$here/check.sh" "$out" "$ecosystem"
