#!/bin/sh
# Boots a cloud image under QEMU with cloud-init and runs the release .deb on a real
# OS with systemd, over SSH: install, setup, service health, sandbox, the
# /var/lib/vmmon move, upgrade, remove and purge. The Docker tier has no systemd.
# Usage: vm.sh IMAGE DEB
# IMAGE is a Debian 13 genericcloud or Ubuntu 24.04 cloud image (qcow2), amd64. It
# is never modified: the VM runs on a throwaway overlay. DEB is the release .deb.
#
# Needs on the host: qemu-system-x86_64, qemu-img, ssh, scp, ssh-keygen and one of
# cloud-localds, genisoimage, mkisofs or xorriso. The guest needs python3 (the
# cloud images have it) and a route to the vulnerability sources if VM_SYNC=1.
#
# Telegram is a fake server inside the VM (set through telegram.api_base_url), so
# no real bot or token is involved. The vulnerability sources are the real ones,
# unless VMMON_OSV_BASE_URL, VMMON_KEV_URL or VMMON_EPSS_URL are set here: they
# are copied into the guest's config.yaml (db.osv_base_url, db.kev_url, db.epss_url).
#
# Environment:
#   VM_SYNC          1 waits for a finished database sync and scans, 0 skips them.
#                    Default 1 with KVM, 0 without: under TCG the Ubuntu sync is too slow.
#   VM_REQUIRE_KVM   1 fails when /dev/kvm is unusable instead of falling back to TCG.
#   VM_MEM, VM_CPUS  guest memory in MiB (default 2048) and CPUs (default 2).
#   VM_BOOT_TIMEOUT  seconds to wait for SSH. Default 300 with KVM, 1800 without.
#   VM_SYNC_TIMEOUT  seconds to wait for the sync. Default 1200 with KVM, 7200 without.
#   VM_KEEP          1 keeps the work directory (overlay, serial log, key) for debugging.
set -eu

die() {
	printf 'vm check failed: %s\n' "$1" >&2
	exit 1
}

[ $# -eq 2 ] || die "usage: vm.sh IMAGE DEB"
image="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
deb="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
[ -f "$image" ] || die "no image at $image"
[ -f "$deb" ] || die "no .deb at $deb"

for tool in qemu-system-x86_64 qemu-img ssh scp ssh-keygen; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
seed_tool=""
for tool in cloud-localds genisoimage mkisofs xorriso; do
	if command -v "$tool" >/dev/null 2>&1; then
		seed_tool="$tool"
		break
	fi
done
[ -n "$seed_tool" ] || die "need cloud-localds, genisoimage, mkisofs or xorriso to build the cloud-init seed"

# KVM when the runner has it, else TCG, which works anywhere but is 10 to 50 times slower.
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	accel="kvm"
	cpu="host"
	default_sync=1
	default_boot=300
	default_sync_timeout=1200
else
	[ "${VM_REQUIRE_KVM:-0}" != 1 ] || die "/dev/kvm is not usable and VM_REQUIRE_KVM=1"
	printf 'warning: no usable /dev/kvm, falling back to TCG: slow, with long timeouts and no database sync by default\n' >&2
	accel="tcg"
	cpu="max"
	default_sync=0
	default_boot=1800
	default_sync_timeout=7200
fi
sync="${VM_SYNC:-$default_sync}"
boot_timeout="${VM_BOOT_TIMEOUT:-$default_boot}"
sync_timeout="${VM_SYNC_TIMEOUT:-$default_sync_timeout}"

work="$(mktemp -d)"
pidfile="$work/qemu.pid"
cleanup() {
	if [ -f "$pidfile" ]; then
		kill "$(cat "$pidfile")" 2>/dev/null || true
	fi
	if [ "${VM_KEEP:-0}" = 1 ]; then
		printf 'kept %s\n' "$work" >&2
	else
		rm -rf "$work"
	fi
}
trap cleanup EXIT

# A free-enough port: pick at random in the ephemeral range and let qemu fail if taken.
port="$(awk 'BEGIN { srand(); print 20000 + int(rand() * 20000) }')"

ssh-keygen -q -t ed25519 -N '' -f "$work/key"
pubkey="$(cat "$work/key.pub")"

cat >"$work/meta-data" <<EOF
instance-id: vmmon-vm-$$
local-hostname: vmmon-vm
EOF
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - $pubkey
ssh_pwauth: false
EOF

case "$seed_tool" in
cloud-localds)
	cloud-localds "$work/seed.iso" "$work/user-data" "$work/meta-data"
	;;
xorriso)
	xorriso -as mkisofs -quiet -output "$work/seed.iso" -volid cidata -joliet -rock \
		"$work/user-data" "$work/meta-data"
	;;
*)
	"$seed_tool" -quiet -output "$work/seed.iso" -volid cidata -joliet -rock \
		"$work/user-data" "$work/meta-data"
	;;
esac

qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/disk.qcow2" 10G

printf 'booting %s with %s (ssh on 127.0.0.1:%s)\n' "$(basename "$image")" "$accel" "$port"
qemu-system-x86_64 \
	-machine "q35,accel=$accel" -cpu "$cpu" \
	-m "${VM_MEM:-2048}" -smp "${VM_CPUS:-2}" \
	-display none -serial "file:$work/serial.log" \
	-drive "file=$work/disk.qcow2,if=virtio,format=qcow2" \
	-drive "file=$work/seed.iso,if=virtio,format=raw,media=cdrom,readonly=on" \
	-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$port-:22" \
	-pidfile "$pidfile" -daemonize

ssh_opts="-i $work/key -o Port=$port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5"
# The options are plain words without spaces in their values, so splitting is wanted.
# Arguments are meant to expand on the client side (SC2029).
# shellcheck disable=SC2086,SC2029
vmssh() { ssh $ssh_opts tester@127.0.0.1 "$@"; }

serial_tail() {
	printf -- '--- last of the serial console ---\n' >&2
	tail -n 40 "$work/serial.log" >&2 || true
}

elapsed=0
until vmssh true 2>/dev/null; do
	elapsed=$((elapsed + 5))
	if [ "$elapsed" -ge "$boot_timeout" ]; then
		serial_tail
		die "no SSH after ${boot_timeout}s"
	fi
	if ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
		serial_tail
		die "qemu exited during boot"
	fi
	sleep 5
done
printf 'ssh is up after about %ss\n' "$elapsed"

# cloud-init exits non-zero when degraded, which does not matter here.
vmssh sudo cloud-init status --wait >/dev/null 2>&1 || true

# shellcheck disable=SC2086
scp $ssh_opts "$deb" tester@127.0.0.1:/tmp/vmmon.deb

# The checks that run inside the guest, as root. POSIX sh.
cat >"$work/guest.sh" <<'GUEST'
set -eu

sync="$1"
sync_timeout="$2"
# "-" stands for an unset URL: ssh drops empty arguments.
osv_url="${3#-}"
kev_url="${4#-}"
epss_url="${5#-}"

die() {
	printf 'guest check failed: %s\n' "$1" >&2
	exit 1
}

step() { printf '== %s\n' "$1"; }

# aptq waits for the lock, since unattended-upgrades may be running at first boot.
aptq() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 -y -q "$@"; }

# wait_for SECONDS DESCRIPTION CMD...: polls every 5 s.
wait_for() {
	limit="$1"
	what="$2"
	shift 2
	waited=0
	until "$@" >/dev/null 2>&1; do
		waited=$((waited + 5))
		[ "$waited" -lt "$limit" ] || die "timed out after ${limit}s waiting for $what"
		sleep 5
	done
}

prop() { systemctl show vmmon -p "$1" --value; }

step "install the .deb"
chmod 644 /tmp/vmmon.deb
aptq install /tmp/vmmon.deb
vmmon version | grep -q '^vmmon .*linux/amd64)$' || die "vmmon version: $(vmmon version)"
systemctl cat vmmon >/dev/null || die "systemd does not find the unit"
test -f /usr/lib/systemd/system/vmmon.service || die "unit not in /usr/lib/systemd/system"
# A fresh install has no token yet, so the package does not start the service.
if systemctl is-active --quiet vmmon; then die "the service is running before setup"; fi

step "fake Telegram and a pre-existing plain /var/lib/vmmon"
cat >/usr/local/lib/faketg.py <<'PY'
import http.server, json

class H(http.server.BaseHTTPRequestHandler):
    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        with open("/var/log/faketg.log", "a") as f:
            f.write(self.path.split("/")[-1] + "\n")
        body = json.dumps({"ok": True, "result": {
            "id": 1, "is_bot": True, "first_name": "fake", "username": "fakebot",
            "url": "", "message_id": 1, "chat": {"id": 123, "type": "private"}}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = _reply
    def log_message(self, *a):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", 8081), H).serve_forever()
PY
: >/var/log/faketg.log
systemd-run --quiet --unit=faketg python3 /usr/local/lib/faketg.py
wait_for 30 "the fake Telegram server" python3 -c 'import urllib.request as u; u.urlopen("http://127.0.0.1:8081/ping")'
: >/var/log/faketg.log

mkdir -p /etc/vmmon
{
	echo "telegram:"
	echo "  api_base_url: http://127.0.0.1:8081"
	if [ -n "$osv_url$kev_url$epss_url" ]; then
		echo "db:"
		[ -z "$osv_url" ] || echo "  osv_base_url: $osv_url"
		[ -z "$kev_url" ] || echo "  kev_url: $kev_url"
		[ -z "$epss_url" ] || echo "  epss_url: $epss_url"
	fi
} >/etc/vmmon/config.yaml
chmod 755 /etc/vmmon
chmod 644 /etc/vmmon/config.yaml

# As if `sudo vmmon db sync` had run before the first service start.
mkdir -p /var/lib/vmmon
echo kept >/var/lib/vmmon/marker

step "vmmon setup"
echo '123456:ABCdefGhIJKlmNoPQRsTUVwxyZ0123456789' >/tmp/token
vmmon setup telegram --token-file /tmp/token --chat-id 123 --policy quiet --yes
rm -f /tmp/token
grep -qx getMe /var/log/faketg.log || die "setup did not check the token"
grep -qx sendMessage /var/log/faketg.log || die "setup did not send the test message"
grep -q 'chat_id:.*123' /etc/vmmon/config.yaml || die "config.yaml lacks the chat id"
grep -q '^VMMON_TELEGRAM_TOKEN=' /etc/vmmon/secrets.env || die "secrets.env lacks the token"
grep -q 'api_base_url' /etc/vmmon/config.yaml || die "setup dropped the existing config"

step "the service is up and /var/lib/vmmon moved under /var/lib/private"
wait_for 60 "the service to be active" systemctl is-active --quiet vmmon
test -L /var/lib/vmmon || die "/var/lib/vmmon is not a symlink"
test -d /var/lib/private/vmmon || die "/var/lib/private/vmmon is missing"
test "$(cat /var/lib/private/vmmon/marker)" = kept || die "the plain directory's contents were lost in the move"
test "$(stat -c %a /var/lib/private)" = 700 || die "/var/lib/private is not 0700"
systemctl is-enabled --quiet vmmon || die "the service is not enabled"

step "unit verifies and the sandbox is in force"
verify="$(systemd-analyze verify /usr/lib/systemd/system/vmmon.service 2>&1 || true)"
test -z "$verify" || die "systemd-analyze verify: $verify"
test "$(prop MemoryMax)" = 1073741824 || die "MemoryMax is $(prop MemoryMax)"
test "$(prop DynamicUser)" = yes || die "DynamicUser is $(prop DynamicUser)"
test "$(prop ProtectSystem)" = strict || die "ProtectSystem is $(prop ProtectSystem)"
test "$(prop NoNewPrivileges)" = yes || die "NoNewPrivileges is $(prop NoNewPrivileges)"
pid="$(prop MainPID)"
test "$pid" -gt 0 || die "no main pid"
test "$(stat -c %U "/proc/$pid")" != root || die "the daemon runs as root"
systemd-analyze security vmmon --no-pager || true

if [ "$sync" = 1 ]; then
	step "wait for the first database sync"
	synced() {
		out="$(vmmon db status --json)" || return 1
		printf '%s' "$out" | grep -Eq '"synced": *true' || return 1
		! printf '%s' "$out" | grep -Eq '"synced": *false|"last_error"'
	}
	wait_for "$sync_timeout" "the first sync" synced
	vmmon db status || true
	step "scan"
	vmmon scan >/tmp/scan.txt || die "vmmon scan failed: $(cat /tmp/scan.txt)"
	vmmon status >/dev/null || die "vmmon status failed"
else
	step "database sync skipped (VM_SYNC=0)"
	sleep 20
fi

step "journal has no sandbox denials, no OOM, no restarts"
journalctl -u vmmon --no-pager >/tmp/vmmon.journal
if grep -Ei 'Permission denied|Operation not permitted|Read-only file system' /tmp/vmmon.journal; then
	die "the journal shows sandbox denials (above)"
fi
if grep -Ei '\boom|out of memory' /tmp/vmmon.journal; then
	die "the journal mentions OOM (above)"
fi
if journalctl -k --no-pager | grep -Ei 'Killed process.*vmmon|oom-kill.*vmmon\.service'; then
	die "the kernel OOM-killed vmmon"
fi
test "$(prop NRestarts)" = 0 || die "NRestarts is $(prop NRestarts)"
systemctl is-active --quiet vmmon || die "the service is not active at the end of the checks"
systemctl show vmmon -p MemoryPeak,MemoryCurrent,NRestarts

step "upgrade: a running service restarts, a stopped one stays stopped"
inv="$(prop InvocationID)"
aptq install --reinstall /tmp/vmmon.deb
wait_for 60 "the service to be active after the reinstall" systemctl is-active --quiet vmmon
test "$(prop InvocationID)" != "$inv" || die "a running service was not restarted by the package"
systemctl stop vmmon
aptq install --reinstall /tmp/vmmon.deb
if systemctl is-active --quiet vmmon; then die "a stopped service was started by the package"; fi

step "apt remove keeps /etc/vmmon and data"
aptq remove vmmon
test ! -e /usr/local/bin/vmmon || die "binary survived remove"
test ! -e /usr/lib/systemd/system/vmmon.service || die "unit survived remove"
test -f /etc/vmmon/secrets.env || die "remove deleted settings"
test -f /etc/vmmon/config.yaml || die "remove deleted the config"
test -d /var/lib/private/vmmon || die "remove deleted data"

step "apt purge deletes them"
aptq purge vmmon
test ! -e /etc/vmmon || die "purge left /etc/vmmon"
test ! -e /var/lib/private/vmmon || die "purge left /var/lib/private/vmmon"
test ! -L /var/lib/vmmon || die "purge left the /var/lib/vmmon symlink"

echo "ok: vm install, setup, service, upgrade, remove, purge"
GUEST

status=0
# shellcheck disable=SC2086,SC2029
ssh $ssh_opts tester@127.0.0.1 sudo sh -s -- "$sync" "$sync_timeout" \
	"${VMMON_OSV_BASE_URL:--}" "${VMMON_KEV_URL:--}" "${VMMON_EPSS_URL:--}" \
	<"$work/guest.sh" || status=$?

if [ "$status" -ne 0 ]; then
	printf -- '--- vmmon journal in the guest ---\n' >&2
	vmssh sudo journalctl -u vmmon --no-pager -n 80 >&2 2>/dev/null || true
	serial_tail
	die "guest checks failed (exit $status)"
fi

# Power off and give qemu a moment; cleanup kills it if it lingers.
vmssh sudo systemctl poweroff >/dev/null 2>&1 || true
waited=0
while kill -0 "$(cat "$pidfile")" 2>/dev/null && [ "$waited" -lt 60 ]; do
	waited=$((waited + 1))
	sleep 1
done
echo "ok: $(basename "$image") on $accel"
