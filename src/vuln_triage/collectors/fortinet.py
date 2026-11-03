from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime

import requests

from vuln_triage.models import Advisory, VersionRange

RSS_URL = "https://www.fortiguard.com/rss/ir.xml"
CSAF_LINK_TAG = "{https://fortiguard.fortinet.com/rss/ns/csaf}link"
HEADERS = {"User-Agent": "vuln-triage/0.1 (+https://github.com/Achrafelq/vuln-triage)"}

VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
BOUND_RE = re.compile(r"(?P<op><=|>=|<|>)\s*(?P<version>\d+(?:\.\d+)+)")
REMEDIATION_RE = re.compile(r"^(?P<product>\S+)\s+(?P<branch>\d+\.\d+):\s*(?P<action>.+)$")


def fetch_index(timeout: int = 30) -> list[str]:
    """URLs des fichiers CSAF listés dans le flux RSS."""
    resp = requests.get(RSS_URL, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    return sorted({el.text.strip() for el in root.iter(CSAF_LINK_TAG) if el.text})


def fetch_csaf(url: str, timeout: int = 30) -> dict:
    """Télécharge un fichier CSAF Fortinet."""
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _clean(product_id: str) -> tuple[str, str]:
    """'FortiOS/ 8.0 all versions' -> ('FortiOS', '8.0 all versions')."""
    text = product_id.replace("/", " ").replace("-upcoming", " ")
    text = re.sub(r"\s+", " ", text).strip()
    product, _, rest = text.partition(" ")
    return product, rest.strip()


def _ranges_from_id(product_id: str, status: str) -> list[VersionRange]:
    """Traduit une chaîne de product_status en plages."""
    product, rest = _clean(product_id)
    if not rest:
        return []
    if "all versions" in rest:
        branch = VERSION_RE.search(rest)
        return [VersionRange(product, "~", branch.group(0), status)] if branch else []
    bounds = BOUND_RE.findall(rest)
    if bounds:
        return [VersionRange(product, op, version, status) for op, version in bounds]
    if VERSION_RE.fullmatch(rest):
        return [VersionRange(product, ">=", rest, "fixed")]
    return []


def _ranges_from_remediation(details: str) -> list[VersionRange]:
    """'FortiOS 7.6: Upgrade to upcoming 7.6.9 or above' -> plage corrigée."""
    out: list[VersionRange] = []
    for line in details.splitlines():
        m = REMEDIATION_RE.match(line.strip())
        if not m:
            continue
        action = m["action"]
        if "Migrate" in action:
            out.append(VersionRange(m["product"], "~", m["branch"], "migrate"))
        elif "Upgrade" in action:
            version = VERSION_RE.search(action)
            if version:
                out.append(VersionRange(m["product"], ">=", version.group(0), "fixed"))
    return out


def parse(data: dict) -> list[Advisory]:
    """Un CSAF Fortinet peut couvrir plusieurs CVE : un Advisory par CVE."""
    doc = data["document"]
    tracking = doc["tracking"]
    published = datetime.fromisoformat(tracking["initial_release_date"]).date()
    updated = datetime.fromisoformat(tracking["current_release_date"]).date()

    by_cve: dict[str, dict] = {}
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if not cve:
            continue
        acc = by_cve.setdefault(cve, {"ranges": [], "cvss": None, "description": ""})
        status = vuln.get("product_status", {})
        for pid in status.get("known_affected", []):
            acc["ranges"] += _ranges_from_id(pid, "affected")
        for pid in status.get("known_not_affected", []):
            acc["ranges"] += _ranges_from_id(pid, "not_affected")
        for rem in vuln.get("remediations", []):
            acc["ranges"] += _ranges_from_remediation(rem.get("details", ""))
        for score in vuln.get("scores", []):
            metric = score.get("cvss_v4") or score.get("cvss_v3") or {}
            if "baseScore" in metric:
                acc["cvss"] = max(acc["cvss"] or 0.0, float(metric["baseScore"]))
        if not acc["description"]:
                        acc["description"] = next(
                (
                    n.get("text", "").strip()
                    for n in vuln.get("notes", [])
                    if n.get("category") == "summary"
                ),
                "",
            )

    return [
        Advisory(
            cve_id=cve,
            vendor="Fortinet",
            title=doc.get("title", ""),
            published=published,
            updated=updated,
            cvss=acc["cvss"],
            vendor_says_exploited="exploited in the wild" in acc["description"].lower(),
            description=acc["description"],
            ranges=tuple(acc["ranges"]),
        )
        for cve, acc in by_cve.items()
    ]


def load(urls: list[str] | None = None) -> dict[str, Advisory]:
    """Avis Fortinet : ceux demandés, sinon ceux du RSS."""
    out: dict[str, Advisory] = {}
    for url in urls if urls is not None else fetch_index():
        for adv in parse(fetch_csaf(url)):
            out[adv.cve_id] = adv
    return out