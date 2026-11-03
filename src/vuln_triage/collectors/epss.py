from __future__ import annotations

from datetime import date

import requests

from vuln_triage.models import EpssScore

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100


def chunks(items: list[str], size: int) -> list[list[str]]:
    """Découpe une liste en paquets de `size` éléments."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def fetch(cve_ids: list[str], timeout: int = 30) -> dict:
    """Demande les scores d'un paquet de CVE (100 max) à l'API EPSS."""
    resp = requests.get(EPSS_URL, params={"cve": ",".join(cve_ids)}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def parse(data: dict) -> dict[str, EpssScore]:
    """Transforme la réponse brute en dict {cve_id: EpssScore}."""
    scores: dict[str, EpssScore] = {}
    for item in data.get("data", []):
        score = EpssScore(
            cve_id=item["cve"],
            epss=float(item["epss"]),
            percentile=float(item["percentile"]),
            date=date.fromisoformat(item["date"]),
        )
        scores[score.cve_id] = score
    return scores


def load(cve_ids: list[str]) -> dict[str, EpssScore]:
    """Scores EPSS pour toutes les CVE demandées, par paquets."""
    scores: dict[str, EpssScore] = {}
    for batch in chunks(sorted(set(cve_ids)), BATCH_SIZE):
        scores.update(parse(fetch(batch)))
    return scores