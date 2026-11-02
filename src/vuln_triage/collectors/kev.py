from __future__ import annotations

from datetime import date

import requests

from vuln_triage.models import KevEntry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(timeout: int = 30) -> dict:
    """Télécharge le catalogue KEV brut (JSON)."""
    resp = requests.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def parse(data: dict) -> dict[str, KevEntry]:
    """Transforme le JSON brut en dict {cve_id: KevEntry}."""
    entries: dict[str, KevEntry] = {}
    for item in data["vulnerabilities"]:
        entry = KevEntry(
            cve_id=item["cveID"],
            vendor=item["vendorProject"],
            product=item["product"],
            name=item["vulnerabilityName"],
            date_added=date.fromisoformat(item["dateAdded"]),
            due_date=date.fromisoformat(item["dueDate"]),
            ransomware=item.get("knownRansomwareCampaignUse") == "Known",
        )
        entries[entry.cve_id] = entry
    return entries


def load() -> dict[str, KevEntry]:
    return parse(fetch())