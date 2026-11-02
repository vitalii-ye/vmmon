# Release checklist

Manual steps that need a person, real accounts or real VMs.

## Before the first tag

1. Make the `vitalii-ye/vmmon` repo public, with `packaging/install.sh` and these workflows on `main`. The install commands download anonymously.
2. Confirm CI is green, including the `integration` job, which has never run.
3. Create the public `vitalii-ye/homebrew-tap` repo with a `main` branch.
4. Create a fine-grained token with Contents read and write on that repo only, and save it as the `HOMEBREW_TAP_TOKEN` Actions secret on `vitalii-ye/vmmon`. Without it a release still succeeds and skips the tap.

## Each release

1. Tag and push: `git tag v0.1.0 && git push <remote> v0.1.0`. Check the remote's name first: it is `ori` in the working copy.
2. Check the release has `vmmon_linux_{amd64,arm64}.tar.gz`, `.deb` and `checksums.txt`, and that the tap has `Casks/vmmon.rb`.

## Fresh-VM end-to-end

On fresh Debian 12 and Ubuntu 24.04 VMs, amd64 and arm64, with a real bot, following only the README:

1. Install with the script on some VMs and the `.deb` on others, then run `sudo vmmon setup`. The test message and first summary arrive.
2. `systemctl status vmmon` is active, and `systemctl cat vmmon` finds the unit.
3. Confirm the sandbox does not break syncing. On Ubuntu, `sudo vmmon db status` shows a finished full sync with no last error, and `journalctl -u vmmon` shows no `Permission denied`, `Operation not permitted` or `Read-only file system`. Watch for failures from `SystemCallFilter`, whose errors appear as EPERM.
4. Check `MemoryMax=1G` during the first Ubuntu sync on a small VM: `systemctl show vmmon -p MemoryPeak,NRestarts` (MemoryPeak needs systemd 256; otherwise read `MemoryCurrent` during the sync). No OOM kill, no restart.
5. `systemd-analyze verify /etc/systemd/system/vmmon.service` (or the `/usr/lib` path) is clean, and `systemd-analyze security vmmon` shows no surprises.
6. `sudo vmmon scan`, `sudo vmmon status` and `sudo vmmon notify test` work. `vmmon status` without sudo points to sudo.
7. Run `sudo vmmon db sync` before a first service start on a spare VM, then set up. Confirm systemd moves the plain `/var/lib/vmmon` to `/var/lib/private/vmmon` and the service can write there.
8. With the service already running, run `sudo vmmon db sync`, then confirm the service still syncs and rescans: root-created files must stay writable by its dynamic user.
9. Install an old vulnerable package: one alert arrives. Upgrade it: the next digest reports it resolved.
10. Upgrade the `.deb` with the service running: it restarts on the new binary. With it stopped: it stays stopped.
11. `apt remove` keeps `/etc/vmmon` and data, and `apt purge` deletes them. Run the README's script uninstall steps too.
12. Homebrew on one Linux host: the cask installs, and its caveat commands give a running service.

## M7 dogfood, 7 days on own VMs

- Idle RSS under 30 MB, scan under 10 s, binary under 25 MB (ADR targets), and peak RSS in a full sync near 250 MB.
- Zero duplicate alerts, including across restarts and upgrades.
- Review the noise and tune the `quiet` thresholds if needed.

## Follow-ups

- Sign releases. Cosign keyless or GitHub artifact attestations need no stored secret, only `id-token: write`, but cannot be tried locally, so they wait for a first real release. `install.sh` would then verify them too.
