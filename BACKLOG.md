# Backlog

Ideas deliberately left out of the current scope, and why.

## Data sources

- **Full advisory history.** The vendor RSS feeds only list recent advisories (about 15 for Palo Alto, about 50 for Fortinet). Good enough for a daily run; a backfill would need each vendor's CSAF `provider-metadata.json`, which was not reachable when this was written.
- **NVD.** Not used: CVSS comes straight from the vendor advisories.
- **Disk cache for CSAF files.** `collect` runs in under a minute, so it is not worth it for a daily job.
- **Panorama.** Read the versions of every managed firewall in one request instead of one call per device.
- **More vendors.** F5 first, then Cisco, Ivanti and Citrix.

## Matching and scoring

- **Panorama-only advisories.** The CSAF product is just "PAN-OS"; some advisories (e.g. CVE-2026-0318) only affect Panorama, which is stated only in the description. They are reported on firewalls too, on purpose (false positive rather than false negative).
- **Exposure read from the device.** Compare the interfaces and portals actually enabled with what the inventory declares.
- **KEV entry on a third-party component** (PHP, Node.js inside a vendor product): P0 or P1? To be decided in `rules.yaml`.
- **Multi-CVE Fortinet advisories.** The "exploited" flag applies to every CVE in the advisory; this is an approximation.
- **Same CVE from two vendors** (e.g. CVE-2026-109618): already deduplicated per device, could be merged in the report.

## Operations

- **Daily report on a machine that sees the network.** Small admin VM in the lab (management network) with `cron` running `vuln-triage run --inventory inventory.yaml` every morning.
- **Daily example report on GitHub**, as a public demo.
