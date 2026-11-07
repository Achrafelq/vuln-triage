from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from vuln_triage.collectors import epss, fortinet, kev, paloalto
from vuln_triage.models import Advisory, EpssScore, KevEntry

log = logging.getLogger(__name__)


def gather_advisories(errors: list[str]) -> list[Advisory]:
    """Palo Alto and Fortinet advisories. Every failure goes to `errors`; nothing blocks."""
    advisories: list[Advisory] = []

    try:
        pa_ids = paloalto.fetch_index()
    except Exception as exc:
        errors.append(f"Palo Alto: RSS index unreachable ({exc})")
        pa_ids = []
    for cve_id in pa_ids:
        try:
            advisories.append(paloalto.parse(paloalto.fetch_csaf(cve_id)))
        except Exception as exc:
            errors.append(f"Palo Alto {cve_id} skipped ({exc})")

    try:
        ft_urls = fortinet.fetch_index()
    except Exception as exc:
        errors.append(f"Fortinet: RSS index unreachable ({exc})")
        ft_urls = {}
    for url in ft_urls:
        try:
            advisories.extend(fortinet.parse(fortinet.fetch_csaf(url), ft_urls[url]))
        except Exception as exc:
            errors.append(f"Fortinet {url} skipped ({exc})")

    for err in errors:
        log.warning(err)
    log.info("%d vendor advisories collected", len(advisories))
    return advisories

def enrich(
    advisories: list[Advisory],
    kev_entries: dict[str, KevEntry],
    epss_scores: dict[str, EpssScore],
) -> list[dict]:
    """Attach to each advisory its KEV entry and EPSS score (or None)."""
    records: list[dict] = []
    for adv in advisories:
        record = asdict(adv)
        k = kev_entries.get(adv.cve_id)
        e = epss_scores.get(adv.cve_id)
        record["kev"] = asdict(k) if k else None
        record["epss"] = asdict(e) if e else None
        records.append(record)
    return records


def collect(out: Path) -> int:
    """Vendors -> KEV -> EPSS -> JSON file. Returns the number of advisories written."""
    errors: list[str] = []
    advisories = gather_advisories(errors)
    kev_entries = kev.load()
    epss_scores = epss.load([a.cve_id for a in advisories])

    records = enrich(advisories, kev_entries, epss_scores)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "count": len(records),
        "errors": errors,
        "advisories": records,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, default=str))
    return len(records)