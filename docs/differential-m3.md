# M3 differential: vmmon vs osv-scanner

- **Date:** 2026-11-02
- **Tools:** osv-scanner 2.7.0 and vmmon at the M3 commit, on macOS arm64
- **Result:** one real vmmon bug found and fixed. After the fix, vmmon reports no (package, CVE) pair that osv-scanner lacks and has no real fix-version differences. Every remaining difference is explained below.

## Method

The plan calls for pinned old container images. Docker was not available, so the fixtures are `dpkg status` files built from public `Packages` indexes with their real `Source:` fields, scanned with `osv-scanner scan source -L dpkg-status:PATH --all-vulns` and `vmmon scan --json --root`. No data from a real host was sent anywhere.

The ecosystems ran one at a time, each scanner invocation alone under a watchdog that kills it above 8 GB of RSS or footprint. An earlier osv-scanner run reached 50 GB on the 16 GB development machine, so the guard is required for anyone repeating this. That run's logs do not record its cause; only the Ubuntu `all.zip` was in its offline cache.

| Ecosystem | osv-scanner mode | Data alignment |
| --- | --- | --- |
| Debian:12 | Offline | Byte-identical: the same `all.zip` sha256 (`aee5ad2d…`) in both tools |
| Ubuntu:24.04:LTS | Online API | Live API against a vmmon DB incrementally synced just before, with 0 records changed |

Comparison is on (source package, CVE) pairs. Ubuntu kernels could not go through osv-scanner: hydrating over 10,000 `linux` records made the API drop the stream (`INTERNAL_ERROR`, after 157 s and 1.8 GB). They were compared at record-ID level through the `querybatch` API instead, sending only the public package name and version.

## Results

| Fixture | Packages | osv-scanner pairs | vmmon pairs | Both | Only osv-scanner | Only vmmon | Real fix differences | osv-scanner peak |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Debian 12, old | 583 | 12,253 | 12,106 | 12,106 | 147 | 0 | 0 | 1.18 GB |
| Debian 12, mid | 584 | 9,952 | 9,795 | 9,795 | 157 | 0 | 0 | 1.02 GB |
| Ubuntu 24.04, old, no kernel | 494 | 1,578 | 1,570 | 1,570 | 8 | 0 | 0 | 1.85 GB |
| Ubuntu 24.04, updated, no kernel | 514 | 433 | 407 | 407 | 26 | 0 | 0 | 0.13 GB |

Kernel by record ID, Ubuntu `linux`:

| Fixture | Kernel | API IDs | vmmon IDs | Both | Only API | Only vmmon |
| --- | --- | --- | --- | --- | --- | --- |
| Old | 6.8.0-31.31 | 10,282 | 10,282 | 10,282 | 0 | 0 |
| Updated | 6.8.0-147.147 | 3,208 | 3,205 | 3,205 | 3 | 0 |

## Differences explained

### Bug found and fixed: USNs naming CVEs only through sibling IDs

Some USNs list their CVEs only as `UBUNTU-CVE-*`. `USN-8239-1` is one, and `UBUNTU-CVE-2026-23918` has no noble entry at all, so that USN is the only link to the CVE on 24.04. vmmon recognised `UBUNTU-CVE-X` only as a record's own ID, so these became findings named `USN-…`. This cost KEV and EPSS lookups, kept regression notices from merging and double-counted findings.

On the old Ubuntu fixture, before and after the fix: only-vmmon pairs 67 → 0, only-osv-scanner pairs 34 → 8, KEV-listed findings 4 → 5. The recovered one is `kmod` CVE-2026-31431, KEV-listed with a fix available, previously hidden behind `USN-8226-1`.

The fix treats these IDs as naming the CVE, with one limit: a CVE reached only through a sibling ID cannot mark a version as patched. A USN listing many CVEs across releases may not fix each on this one, and `python3.12` CVE-2025-15366 and -15367 show the risk. Letting sibling links suppress findings would have hidden them.

### Expected: osv-scanner false positives from binary versions

All samba differences (147 and 157 on Debian, 4 on old Ubuntu, 19 on updated Ubuntu). `libldb2` has `Source: samba (2:4.17.8+dfsg-2)` but binary version `2:2.6.2+samba4.17.8+dfsg-2`. osv-scanner compares the binary version against samba's ranges and reports CVEs fixed in samba 3.x. vmmon uses the source version.

### Expected: withdrawn records

`libxml2` CVE-2025-26434, `lz4` CVE-2025-62813, `pyjwt` CVE-2025-45768 and `python-certifi` CVE-2024-39689 are withdrawn in OSV but still returned. vmmon does not index withdrawn records.

### Expected: unfixed records lagging a fix (deliberate)

Three cases on updated Ubuntu: `libevent` CVE-2026-63387, `protobuf` CVE-2026-6409 and `python-urllib3` CVE-2026-97687. The `UBUNTU-CVE` record has no fixed event, while a USN naming the CVE literally has its fix at or below the installed version (for example `USN-8840-1` at exactly the installed `2.1.12-stable-9ubuntu2.2`). vmmon drops these and osv-scanner keeps them.

The three kernel records (`UBUNTU-CVE-2024-27022`, `-35895`, `-40954`) are the same case: `USN-6893-1` and `USN-6999-1` fixed them at 6.8.0-38 and 6.8.0-44, and the fixture runs 6.8.0-147.

**Residual risk:** a USN naming a CVE literally might still not fix it on this release. The data does not distinguish that case, and all checked examples were genuine lag.

### Deliberate: CVSS base score vs threat-adjusted score

16 pairs on each Debian fixture and 5 and 3 on the Ubuntu fixtures differ in score. Every Debian difference has a CVSS 4.0 `E:P` or `E:U` metric, and so do all those sampled on Ubuntu. vmmon reports the base score, because exploitation evidence already comes from KEV and EPSS. osv-scanner's figure includes the threat metric.

This can change alerts: `glibc` CVE-2026-6791 (9.0 vs 6.6), `pam` CVE-2026-54411 (8.2 vs 6.9) and `unbound` CVE-2025-11411 (7.1 vs 5.7) cross the quiet preset's CVSS ≥ 7 threshold under vmmon only on Debian, and `pam` does on old Ubuntu too.

### Comparison script artifact

20 apparent fix-version differences on old Ubuntu came from crediting a USN's fix to every CVE in osv-scanner's group. In all 20, no record with the higher fix names that CVE.

## Performance of `vmmon scan`

Measured with the final code on the same fixtures. Targets from ADR-001: scan under 10 s, binary under 25 MB.

| Fixture | Findings | KEV | Wall | Peak footprint | Max RSS |
| --- | --- | --- | --- | --- | --- |
| Debian 12, old | 12,106 | 26 | 0.27 s | 64 MB | 78 MB |
| Debian 12, mid | 9,795 | 19 | 0.26 s | 56 MB | 75 MB |
| Ubuntu 24.04, old, with kernel | 11,821 | 17 | 1.09 s | 72 MB | 92 MB |
| Ubuntu 24.04, updated, with kernel | 3,612 | 0 | 1.07 s | 30 MB | 80 MB |

Stripped static Linux binaries: 15.0 MiB (amd64), 14.0 MiB (arm64).

## Not covered

- Debian 13 and Ubuntu 22.04 were not differentially tested. Their matching is covered by unit and inventory fixtures only.
- The container-image differential from the plan remains open for a machine with Docker. These fixtures are realistic but synthetic, and nothing here ran on Linux.
- Kernel comparison is by record ID for one source and two versions: `reboot_required` and cloud or HWE flavours were not compared.
