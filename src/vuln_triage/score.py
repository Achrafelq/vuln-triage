from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from vuln_triage.match import Match
from vuln_triage.models import Device

# Which part of the device does the advisory target? Guessed from the vendor's text.
COMPONENTS = (
    ("mgmt_exposed", "management interface exposed", r"management interface|web interface"),
    ("vpn_portal_enabled", "VPN portal exposed", r"GlobalProtect|SSL-?VPN"),
    ("auth_portal_enabled", "authentication portal exposed", r"Authenticat\w+ Portal|Captive"),
)


@dataclass(frozen=True)
class Rules:
    epss_threshold: float = 0.10
    cvss_threshold: float = 7.0


@dataclass(frozen=True)
class Scored:
    match: Match
    priority: str  # "P0" to "P3"
    reasons: tuple[str, ...]


def load_rules(path: Path) -> Rules:
    data = yaml.safe_load(path.read_text()) or {}
    return Rules(
        epss_threshold=float(data.get("epss_threshold", 0.10)),
        cvss_threshold=float(data.get("cvss_threshold", 7.0)),
    )


def exposure(device: Device, record: dict) -> tuple[bool, str]:
    """Is the vulnerable component reachable from the Internet?"""
    text = f"{record.get('title', '')} {record.get('description', '')}"
    for flag, label, pattern in COMPONENTS:
        if re.search(pattern, text, re.IGNORECASE):
            exposed = getattr(device, flag)
            return exposed, label if exposed else label.replace(" exposed", " not exposed")
    if device.internet_facing:
        return True, "device exposed to the Internet"
    return False, "device not exposed"


def score(m: Match, device: Device, rules: Rules) -> Scored:
    r = m.record
    kev = r.get("kev")
    epss = (r.get("epss") or {}).get("epss")
    cvss = r.get("cvss")
    exploited = bool(kev) or bool(r.get("vendor_says_exploited"))
    exposed, exposure_reason = exposure(device, r)

    reasons: list[str] = []
    if kev:
        reasons.append(f"in KEV since {kev['date_added']}")
    if r.get("vendor_says_exploited"):
        reasons.append("vendor reports active exploitation")
    reasons.append(exposure_reason)
    if epss is not None:
        reasons.append(f"EPSS {epss:.1%}")
    if cvss is not None:
        reasons.append(f"CVSS {cvss}")
    if m.action == "migrate":
        reasons.append("no fix on this branch: migrate")

    if exploited and exposed:
        priority = "P0"
    elif exploited or (epss is not None and epss >= rules.epss_threshold and exposed):
        priority = "P1"
    elif cvss is not None and cvss >= rules.cvss_threshold:
        priority = "P2"
    else:
        priority = "P3"
    return Scored(match=m, priority=priority, reasons=tuple(reasons))


def score_all(matches: list[Match], devices: list[Device], rules: Rules) -> list[Scored]:
    """Score each pair, then sort: P0 first, highest CVSS first."""
    by_name = {d.name: d for d in devices}
    scored = [score(m, by_name[m.device], rules) for m in matches]
    return sorted(scored, key=lambda s: (s.priority, -(s.match.record.get("cvss") or 0)))
