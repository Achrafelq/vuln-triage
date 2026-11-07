from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path

from vuln_triage import match
from vuln_triage.models import Device
from vuln_triage.score import Rules, Scored

PRIORITIES = ("P0", "P1", "P2", "P3")
HEADINGS = {
    "P0": "P0 — act today",
    "P1": "P1 — this week",
    "P2": "P2 — this month",
    "P3": "P3 — next patch cycle",
}
CSV_COLUMNS = [
    "priority", "device", "product", "current_version", "cve", "vendor", "title",
    "action", "fixed_in", "kev_date_added", "epss", "cvss", "reasons",
]


def _todo(s: Scored) -> str:
    m = s.match
    if m.action == "patch":
        return f"upgrade to {m.fixed_in}"
    if m.action == "migrate":
        return "change branch"
    return "no fix published"


def upgrade_plan(scored: list[Scored], devices: list[Device]) -> list[dict]:
    """For each device: ONE target version, and what it really fixes."""
    plan = []
    for device in devices:
        mine = [s for s in scored if s.match.device == device.name]
        targets = [s.match.fixed_in for s in mine if s.match.action == "patch"]
        if not targets:
            continue
        target = max(targets, key=match.parse_version)
        upgraded = replace(device, version=target)
        still = [s for s in mine if match.check(upgraded, s.match.record) is not None]
        plan.append(
            {
                "device": device.name,
                "current": device.version,
                "target": target,
                "fixes": len(mine) - len(still),
                "total": len(mine),
                "still": [s.match.cve_id for s in still],
                "worst": min(s.priority for s in mine),
            }
        )
    return sorted(plan, key=lambda p: (p["worst"], p["device"]))


def render_markdown(
    scored: list[Scored], devices: list[Device], payload: dict, rules: Rules
) -> str:
    counts = {p: sum(1 for s in scored if s.priority == p) for p in PRIORITIES}
    p0 = [s for s in scored if s.priority == "P0"]
    generated = payload.get("generated_at", "")
    day = generated[:10]
    when = f"{generated[:16].replace('T', ' ')} UTC" if generated else "?"

    lines = [f"# vuln-triage report — {day}", ""]
    lines.append(
        f"Generated {when} from {payload.get('count', 0)} vendor "
        f"advisories · {len(devices)} devices · rules: EPSS ≥ {rules.epss_threshold:.0%}, "
        f"CVSS ≥ {rules.cvss_threshold}"
    )
    lines += ["", "## Summary", ""]
    if p0:
        lines.append(f"- **{len(p0)} urgent action(s) (P0)**:")
        lines += [f"  - {s.match.device}: {s.match.cve_id}, {_todo(s)}" for s in p0]
    else:
        lines.append("- **No urgent action (P0).**")
    lines.append("- " + " · ".join(f"{p}: {n}" for p, n in counts.items()))
    errors = payload.get("errors", [])
    if errors:
        lines.append(
            f"- **Warning: incomplete collection ({len(errors)} source error(s)).** "
            "Devices may be affected by advisories that could not be read (see the end)."
        )

    plan = upgrade_plan(scored, devices)
    if plan:
        lines += ["", "## Recommended upgrades", ""]
        lines.append("| Device | Current | Upgrade to | Fixes | Highest priority |")
        lines.append("| --- | --- | --- | --- | --- |")
        for p in plan:
            fixes = f"{p['fixes']} of {p['total']} CVEs"
            if p["still"]:
                fixes += f"; still open, change branch: {', '.join(p['still'])}"
            lines.append(
                f"| {p['device']} | {p['current']} | {p['target']} | {fixes} | {p['worst']} |"
            )

    for prio in PRIORITIES:
        rows = [s for s in scored if s.priority == prio]
        if not rows:
            continue
        lines += ["", f"## {HEADINGS[prio]} ({len(rows)})", ""]
        lines.append("| Device | CVE | Action | Why |")
        lines.append("| --- | --- | --- | --- |")
        for s in rows:
            why = " · ".join(s.reasons)
            lines.append(f"| {s.match.device} | {s.match.cve_id} | {_todo(s)} | {why} |")

    if errors:
        lines += ["", "## Collection errors", ""]
        lines += [f"- {e}" for e in errors]
    return "\n".join(lines) + "\n"


def write_csv(scored: list[Scored], path: Path) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for s in scored:
            m, r = s.match, s.match.record
            writer.writerow(
                {
                    "priority": s.priority,
                    "device": m.device,
                    "product": m.product,
                    "current_version": m.version,
                    "cve": m.cve_id,
                    "vendor": m.vendor,
                    "title": m.title,
                    "action": m.action,
                    "fixed_in": m.fixed_in or "",
                    "kev_date_added": (r.get("kev") or {}).get("date_added", ""),
                    "epss": (r.get("epss") or {}).get("epss", ""),
                    "cvss": r.get("cvss") if r.get("cvss") is not None else "",
                    "reasons": " · ".join(s.reasons),
                }
            )
