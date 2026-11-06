# vmmon

vmmon watches a Debian or Ubuntu VM for known vulnerabilities and tells you on Telegram when a new one affects it. It is one static binary and a systemd service. It keeps a local copy of the [OSV](https://osv.dev) data for your release, rechecks after every database sync and package change, and alerts only on new findings that pass your alert policy.

Supported: Debian 12, 13 and Ubuntu 22.04, 24.04, on amd64 and arm64. The Docker integration tests run on Debian 13 and Ubuntu 24.04.

## Install

You need `sudo`, and `curl` and `ca-certificates`, which minimal images may lack: `sudo apt install -y curl ca-certificates`. The first sync needs free disk: about 1.3 GB on Ubuntu.

**Script.** It verifies the release's sha256 before installing, and does not start anything.

```bash
curl -fsSL https://raw.githubusercontent.com/vitalii-ye/vmmon/main/packaging/install.sh | sh
```

To install a specific release, end the command with `| VMMON_VERSION=1.2.3 sh`.

**Or the `.deb`:**

```bash
arch=$(dpkg --print-architecture)
curl -fsSLO "https://github.com/vitalii-ye/vmmon/releases/latest/download/vmmon_linux_$arch.deb"
curl -fsSLO https://github.com/vitalii-ye/vmmon/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt
sudo apt install "./vmmon_linux_$arch.deb"
```

apt may print a note about the download being unsandboxed. It is harmless.

**Homebrew** (`brew install --cask vitalii-ye/tap/vmmon`) installs the CLI only. Homebrew cannot run the service from its prefix, so to run it, follow the steps the cask prints. For a monitored host, prefer the script or the `.deb`.

## Set up

Create a bot first: message [@BotFather](https://t.me/BotFather) on Telegram, send `/newbot`, and copy the token. One bot can serve all your VMs. Then:

```bash
sudo vmmon setup
```

The wizard asks for the token, shows a link and QR code to pair your chat, sends a test message, asks for an alert policy, saves the settings and starts the service.

For scripts, with the token in a file:

```bash
sudo vmmon setup telegram --token-file PATH --chat-id ID --policy quiet --yes
```

## What arrives in Telegram

| When | Message |
| --- | --- |
| During setup | A test message |
| After the first database sync | One summary of the scan, never one message per old finding. The first Ubuntu sync downloads about 800 MB, so allow a few minutes |
| A new finding passes the policy, within one sync cycle (6 h by default) or 5 minutes after a package change | One alert for all new findings of that scan |
| An open finding becomes KEV-listed, gets a fix or first meets the policy (for example its EPSS rose), and passes the policy | One follow-up alert |
| Daily at 09:00 local (weekly for Critical only) | A digest: open counts, resolved findings, database age, reboot needed |
| The database has not synced for 48 h | A staleness warning |

Every message starts with the hostname, and the same news is never repeated, including across restarts. Upgrading a package resolves its findings, and the next digest says so. A resolved finding that comes back counts as new.

## Alert policy

| Preset | Immediate alert when | Digest |
| --- | --- | --- |
| `quiet` (default) | KEV-listed, or a fix is available with CVSS at or above `min_cvss` (7) or EPSS at or above `min_epss` (0.1) | Daily |
| `critical` | KEV-listed | Weekly |
| `everything` | Any new finding | Daily |

`quiet` also skips non-KEV findings the distro rates `unimportant` or `end-of-life`.

## Commands

Commands that read the service's data or the token need `sudo`.

| Command | Purpose |
| --- | --- |
| `sudo vmmon setup [telegram]` | Interactive wizard. Flags: `--token-file PATH`, `--chat-id ID`, `--policy quiet\|critical\|everything`, `--yes`, `--no-start` |
| `sudo vmmon scan [--json] [--root PATH]` | One-shot scan against the local database, offline. Exits 0 with or without findings |
| `sudo vmmon db sync [--full] [--ecosystem NAME]` | Refresh the database and feeds now |
| `sudo vmmon db status [--json] [--ecosystem NAME]` | Ecosystems, record counts, ages |
| `vmmon daemon` | The long-running loop that systemd starts. You do not normally run it |
| `sudo vmmon status [--json]` | Open findings, database age, pending reboot, last scan, channel health |
| `sudo vmmon notify test` | Send a test message |
| `vmmon inventory [--json] [--root PATH]` | Debug: installed packages with their source names, and kernel state |
| `vmmon version` | Build info |

Every command also takes `--config PATH` and `-v` for debug logging. `vmmon scan` reports "no usable vulnerability database" until the first sync has finished. Follow progress with `sudo journalctl -u vmmon -f`.

## Configuration

`vmmon setup` writes what most people need. Everything else has a default. After editing `/etc/vmmon/config.yaml`, run `sudo systemctl restart vmmon`.

| Key | Default | Meaning |
| --- | --- | --- |
| `hostname` | system hostname | Name used in messages |
| `state_dir` | `/var/lib/vmmon` | Data directory. Another path needs `ReadWritePaths=` in a drop-in |
| `db.sync_interval` | `6h` | Vulnerability database sync |
| `db.full_refresh_interval` | `168h` | Full re-download |
| `db.enrich_interval` | `24h` | KEV and EPSS refresh |
| `db.stale_after` | `48h` | Age that triggers the staleness warning |
| `db.full_sync_threshold` | `5000` | Changed records above which a sync downloads everything |
| `db.osv_base_url` | OSV's bucket | Data source |
| `db.kev_url`, `db.epss_url` | CISA's and FIRST's feeds | Data sources |
| `db.ubuntu_pro` | `false` | Include Ubuntu Pro records |
| `policy.preset` | `quiet` | `quiet`, `critical` or `everything` |
| `policy.min_cvss`, `policy.min_epss` | `7`, `0.1` | `quiet` thresholds |
| `policy.digest_time` | `09:00` | Local time, `HH:MM` |
| `policy.ignore.cves`, `policy.ignore.packages` | empty | Lists to suppress, for OSV data bugs |
| `telegram.chat_id` | set by setup | Chat to send to |
| `telegram.api_base_url` | `https://api.telegram.org` | Bot API base URL |

Unknown keys are an error. Environment variables override the file: `VMMON_CONFIG` (config path), `VMMON_HOSTNAME`, `VMMON_STATE_DIR`, `VMMON_POLICY`, `VMMON_TELEGRAM_TOKEN`, `VMMON_TELEGRAM_CHAT_ID`, `VMMON_TELEGRAM_API_BASE_URL`, `VMMON_OSV_BASE_URL`, `VMMON_KEV_URL`, `VMMON_EPSS_URL`, `VMMON_SYNC_INTERVAL`, `VMMON_UBUNTU_PRO`.

## Files

| Path | Contents |
| --- | --- |
| `/usr/local/bin/vmmon` | The binary |
| `/etc/systemd/system/vmmon.service` | The unit, from the script |
| `/usr/lib/systemd/system/vmmon.service` | The unit, from the `.deb` |
| `/etc/vmmon/config.yaml` | Settings, mode 0644 |
| `/etc/vmmon/secrets.env` | Bot token, mode 0600 |
| `/var/lib/vmmon/` | Data: `db/` and `state.bolt`. A symlink to `/var/lib/private/vmmon` once the service has run |

## Security model

- **Root** is needed only to install and for `vmmon setup`, which writes `/etc/vmmon` and enables the service.
- **The service is unprivileged.** It runs under systemd's `DynamicUser`, with a read-only view of the system, no capabilities and a restricted set of syscalls. It reads the dpkg status file, `os-release`, `/run/reboot-required` and its config, and writes only its own data.
- **`sudo vmmon scan` and `sudo vmmon status` need root** because systemd keeps `DynamicUser` data under `/var/lib/private`, which is mode 0700.
- **The token** is in `secrets.env`, mode 0600. systemd reads that file and passes the token to the service in its environment. It is never written to `config.yaml`, and `vmmon status` shows only whether it is set.
- **No inbound ports.** vmmon listens on nothing, and talks to Telegram by outbound HTTPS only.
- **No telemetry.** Outbound traffic is the OSV bucket on `storage.googleapis.com`, `www.cisa.gov`, `epss.empiricalsecurity.com` and `api.telegram.org`. Only Telegram receives anything about the host: its hostname and the package names, versions and CVEs in your messages.

## Limitations

- Debian 12, 13 and Ubuntu 22.04, 24.04 only, with dpkg. Others get a clear error, and `install.sh` refuses them.
- Telegram is the only channel.
- OSV has no records for some kernel lines, such as `linux-6.12` on Debian 12. Scans then warn that the kernel could not be checked, rather than reporting it clean.
- Bandwidth: the weekly full refresh downloads about 806 MB on Ubuntu and 80 MB on Debian. Syncs in between are small. A full Ubuntu sync peaks near 250 MB of RAM.
- Matching was compared with osv-scanner, and each difference is explained in [docs/differential-m3.md](docs/differential-m3.md).

## Uninstall

Installed with the `.deb`:

```bash
sudo apt remove vmmon   # Keeps settings and data.
sudo apt purge vmmon    # Deletes /etc/vmmon, including the token, and all data.
```

Installed with the script:

```bash
sudo systemctl disable --now vmmon
sudo rm /usr/local/bin/vmmon /etc/systemd/system/vmmon.service
sudo systemctl daemon-reload
sudo rm -rf /etc/vmmon /var/lib/private/vmmon /var/lib/vmmon
```

If the bot served only this host, revoke its token with @BotFather.

## License

[Apache-2.0](LICENSE).
