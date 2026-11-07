from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime

import requests

from vuln_triage.models import Advisory, VersionRange

CSAF_URL = "https://security.paloaltonetworks.com/csaf/{cve_id}"
RSS_URL = "https://security.paloaltonetworks.com/rss.xml"
HEADERS = {"User-Agent": "vuln-triage/0.1 (+https://github.com/Achrafelq/vuln-triage)"}

RANGE_RE = re.compile(r"^vers:generic/(?P<product>[^<>=]+)(?P<op><=|>=|<|>)(?P<version>.+)$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def fetch_index(timeout: int = 30) -> list[str]:
    """Recent CVEs listed in the RSS feed."""
    resp = requests.get(RSS_URL, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    found: set[str] = set()
    for link in root.iter("link"):
        m = CVE_RE.search(link.text or "")
        if m:
            found.add(m.group(0))
    return sorted(found)


def fetch_csaf(cve_id: str, timeout: int = 30) -> dict:
    """Download the CSAF advisory for one CVE."""
    resp = requests.get(CSAF_URL.format(cve_id=cve_id), headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _ranges(branches: list[dict]) -> list[dict]:
    """Walk the product tree and collect every version range."""
    out: list[dict] = []
    for branch in branches:
        if branch.get("category") == "product_version_range":
            out.append(branch)
        out.extend(_ranges(branch.get("branches", [])))
    return out


def parse(data: dict) -> Advisory:
    """Turn a Palo Alto CSAF document into an Advisory."""
    doc = data["document"]
    vuln = data["vulnerabilities"][0]
    fixed_ids = set(vuln.get("product_status", {}).get("fixed", []))

    ranges: list[VersionRange] = []
    for entry in _ranges(data["product_tree"]["branches"]):
        m = RANGE_RE.match(entry["name"])
        if not m:
            continue
        pid = entry["product"]["product_id"]
        status = "affected" if m["op"] in ("<", "<=") or pid not in fixed_ids else "fixed"
        ranges.append(
            VersionRange(product=m["product"], op=m["op"], version=m["version"], status=status)
        )

    cvss: float | None = None
    exploited = False
    for score in vuln.get("scores", []):
        metric = score.get("cvss_v4") or score.get("cvss_v3") or {}
        if "baseScore" in metric:
            cvss = max(cvss or 0.0, float(metric["baseScore"]))
        if metric.get("exploitMaturity") == "ATTACKED":
            exploited = True

    description = next(
        (n["text"] for n in vuln.get("notes", []) if n.get("category") == "description"), ""
    )
    title = next(
        (n["title"] for n in doc.get("notes", []) if n.get("category") == "summary"),
        doc.get("title", ""),
    )

    return Advisory(
        cve_id=vuln["cve"],
        vendor="Palo Alto Networks",
        title=title,
        published=datetime.fromisoformat(doc["tracking"]["initial_release_date"]).date(),
        updated=datetime.fromisoformat(doc["tracking"]["current_release_date"]).date(),
        cvss=cvss,
        vendor_says_exploited=exploited,
        description=description,
        ranges=tuple(ranges),
    )


def load(cve_ids: list[str] | None = None) -> dict[str, Advisory]:
    """Palo Alto advisories: the requested ones, otherwise those in the RSS feed."""
    ids = cve_ids if cve_ids is not None else fetch_index()
    return {cve_id: parse(fetch_csaf(cve_id)) for cve_id in ids}