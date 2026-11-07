from __future__ import annotations

import json
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
EXPLOITED_RE = re.compile(r"(?<!not )(?<!not been )exploited in the wild", re.IGNORECASE)

def fetch_index(timeout: int = 30) -> dict[str, str]:
    """{CSAF url: advisory text from the RSS feed}."""
    resp = requests.get(RSS_URL, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    index: dict[str, str] = {}
    for item in root.iter("item"):
        link = item.find(CSAF_LINK_TAG)
        if link is not None and link.text:
            index[link.text.strip()] = item.findtext("description", default="")
    return index


def fetch_csaf(url: str, timeout: int = 30) -> dict:
    """Download one Fortinet CSAF file."""
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def _says_exploited(text: str) -> bool:
    """Does the vendor say the flaw is exploited?"""
    return bool(EXPLOITED_RE.search(text))


def _clean(product_id: str) -> tuple[str, str]:
    """'FortiOS/ 8.0 all versions' -> ('FortiOS', '8.0 all versions')."""
    text = product_id.replace("/", " ").replace("-upcoming", " ")
    text = re.sub(r"\s+", " ", text).strip()
    product, _, rest = text.partition(" ")
    return product, rest.strip()


def _ranges_from_id(product_id: str, status: str) -> list[VersionRange]:
    """Turn a product_status string into version ranges."""
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
    """'FortiOS 7.6: Upgrade to upcoming 7.6.9 or above' -> fixed range."""
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


def parse(data: dict, rss_text: str = "") -> list[Advisory]:
    """One Fortinet CSAF file can cover several CVEs: one Advisory per CVE."""
    exploited = _says_exploited(json.dumps(data) + " " + rss_text)
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
            vendor_says_exploited=exploited,
            description=acc["description"],
            ranges=tuple(acc["ranges"]),
        )
        for cve, acc in by_cve.items()
    ]


def load(index: dict[str, str] | None = None) -> dict[str, Advisory]:
    """Fortinet advisories: the requested ones, otherwise those in the RSS feed."""
    if index is None:
        index = fetch_index()
    out: dict[str, Advisory] = {}
    for url, rss_text in index.items():
        for adv in parse(fetch_csaf(url), rss_text):
            out[adv.cve_id] = adv
    return out