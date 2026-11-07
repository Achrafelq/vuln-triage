from __future__ import annotations

import re
from dataclasses import dataclass

from vuln_triage.models import Device

VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:-h(\d+))?$")

Version = tuple[int, int, int, int]  # (majeur, mineur, maintenance, hotfix)


def parse_version(text: str) -> Version | None:
    """'11.1.6-h39' -> (11, 1, 6, 39) ; '7.4.8' -> (7, 4, 8, 0) ; illisible -> None."""
    m = VERSION_RE.match(text.strip())
    if not m:
        return None
    major, minor, maint, hotfix = m.groups()
    return (int(major), int(minor), int(maint or 0), int(hotfix or 0))


def _branch(v: Version) -> tuple[int, int]:
    return v[0], v[1]


def _holds(v: Version, op: str, x: Version) -> bool:
    return {"<": v < x, "<=": v <= x, ">": v > x, ">=": v >= x}[op]


@dataclass(frozen=True)
class Match:
    device: str
    product: str
    version: str
    cve_id: str
    vendor: str
    title: str
    action: str  # "patch", "migrate" ou "no_fix"
    fixed_in: str | None  # version à installer quand action == "patch"
    record: dict  # la fiche complète (KEV, EPSS…), pour le scorer


def check(device: Device, record: dict) -> Match | None:
    """Ce firewall est-il touché par cet avis ? None si non."""
    v = parse_version(device.version)
    if v is None:
        raise ValueError(f"{device.name} : version illisible {device.version!r}")
    branch = _branch(v)

    affected_bounds: list[tuple[str, Version]] = []
    whole_branch_affected = False
    migrate = False
    fixed_points: list[tuple[Version, str]] = []

    for r in record["ranges"]:
        if r["product"] != device.product:
            continue
        if r["op"] == "~":  # Fortinet : « toute la branche 7.4 »
            whole = parse_version(r["version"])
            if whole is None or _branch(whole) != branch:
                continue
            if r["status"] == "affected":
                whole_branch_affected = True
            elif r["status"] == "migrate":
                migrate = True
            continue
        x = parse_version(r["version"])
        if x is None or _branch(x) != branch:
            continue
        if r["status"] == "affected":
            affected_bounds.append((r["op"], x))
        elif r["status"] == "fixed" and r["op"] == ">=":
            fixed_points.append((x, r["version"]))

    # Touché si la branche entière est touchée, ou si TOUTES les bornes de la branche sont vraies.
    affected = whole_branch_affected or (
        bool(affected_bounds) and all(_holds(v, op, x) for op, x in affected_bounds)
    )
    if not affected:
        return None

    # Corrigé si un correctif existe sur la même version de maintenance avec un hotfix suffisant,
    # ou si la version est plus récente que TOUS les correctifs publiés pour la branche.
    same_maint = [x for x, _ in fixed_points if x[:3] == v[:3]]
    if any(v >= x for x in same_maint):
        return None
    if fixed_points and v > max(x for x, _ in fixed_points):
        return None

    next_fix = min((p for p in fixed_points if p[0] > v), default=None)
    if migrate and next_fix is None:
        action, fixed_in = "migrate", None
    elif next_fix is not None:
        action, fixed_in = "patch", next_fix[1]
    else:
        action, fixed_in = "no_fix", None

    return Match(
        device=device.name,
        product=device.product,
        version=device.version,
        cve_id=record["cve_id"],
        vendor=record["vendor"],
        title=record["title"],
        action=action,
        fixed_in=fixed_in,
        record=record,
    )


def match_all(devices: list[Device], records: list[dict]) -> list[Match]:
    """Tous les couples (firewall, CVE) touchés, sans doublon."""
    seen: set[tuple[str, str]] = set()
    matches: list[Match] = []
    for device in devices:
        for record in records:
            m = check(device, record)
            if m is not None and (m.device, m.cve_id) not in seen:
                seen.add((m.device, m.cve_id))
                matches.append(m)
    return matches
