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
    """Avis Palo Alto et Fortinet. Toute panne est notée dans `errors`, rien ne bloque."""
    advisories: list[Advisory] = []

    try:
        pa_ids = paloalto.fetch_index()
    except Exception as exc:
        errors.append(f"Palo Alto : index RSS inaccessible ({exc})")
        pa_ids = []
    for cve_id in pa_ids:
        try:
            advisories.append(paloalto.parse(paloalto.fetch_csaf(cve_id)))
        except Exception as exc:
            errors.append(f"Palo Alto {cve_id} ignoré ({exc})")

    try:
        ft_urls = fortinet.fetch_index()
    except Exception as exc:
        errors.append(f"Fortinet : index RSS inaccessible ({exc})")
        ft_urls = []
    for url in ft_urls:
        try:
            advisories.extend(fortinet.parse(fortinet.fetch_csaf(url)))
        except Exception as exc:
            errors.append(f"Fortinet {url} ignoré ({exc})")

    for err in errors:
        log.warning(err)
    log.info("%d avis vendeurs collectés", len(advisories))
    return advisories

def enrich(
    advisories: list[Advisory],
    kev_entries: dict[str, KevEntry],
    epss_scores: dict[str, EpssScore],
) -> list[dict]:
    """Agrafe à chaque avis sa fiche KEV et son score EPSS (ou None)."""
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
    """Vendeurs → KEV → EPSS → fichier JSON. Renvoie le nombre d'avis écrits."""
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