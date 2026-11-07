from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from vuln_triage import inventory, live, match, report, score
from vuln_triage.collect import collect


def _show_inventory(path: Path, use_live: bool) -> None:
    devices = inventory.load(path)
    notes: list[str] = []
    if use_live:
        devices, notes = live.refresh(devices)
    for d in devices:
        exposed = [
            flag
            for flag, on in (
                ("internet", d.internet_facing),
                ("mgmt", d.mgmt_exposed),
                ("vpn", d.vpn_portal_enabled),
                ("auth-portal", d.auth_portal_enabled),
            )
            if on
        ]
        print(f"{d.name:<14} {d.product:<8} {d.version:<12} exposed: {', '.join(exposed) or '-'}")
    for note in notes:
        print(f"! {note}")


def _show_matches(advisories_path: Path, inventory_path: Path) -> None:
    payload = json.loads(advisories_path.read_text())
    devices = inventory.load(inventory_path)
    matches = match.match_all(devices, payload["advisories"])
    for m in matches:
        todo = {"patch": f"upgrade to {m.fixed_in}", "migrate": "change branch"}
        what = todo.get(m.action, "no fix published")
        print(f"{m.device:<14} {m.version:<12} {m.cve_id:<17} {what}")
    print(f"{len(matches)} affected device/CVE pair(s)")
    for err in payload.get("errors", []):
        print(f"! incomplete collection: {err}")


def _show_scores(advisories_path: Path, inventory_path: Path, rules_path: Path) -> None:
    payload = json.loads(advisories_path.read_text())
    devices = inventory.load(inventory_path)
    matches = match.match_all(devices, payload["advisories"])
    results = score.score_all(matches, devices, score.load_rules(rules_path))
    for s in results:
        m = s.match
        todo = {"patch": f"upgrade to {m.fixed_in}", "migrate": "change branch"}
        what = todo.get(m.action, "no fix published")
        print(f"{s.priority}  {m.device:<14} {m.cve_id:<17} {what}")
        print(f"    {' · '.join(s.reasons)}")
    counts = {p: sum(1 for s in results if s.priority == p) for p in ("P0", "P1", "P2", "P3")}
    print(" ".join(f"{p}={n}" for p, n in counts.items()))
    for err in payload.get("errors", []):
        print(f"! incomplete collection: {err}")


def _write_report(
    advisories_path: Path, inventory_path: Path, rules_path: Path, out_dir: Path
) -> None:
    payload = json.loads(advisories_path.read_text())
    devices = inventory.load(inventory_path)
    rules = score.load_rules(rules_path)
    results = score.score_all(match.match_all(devices, payload["advisories"]), devices, rules)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.md").write_text(report.render_markdown(results, devices, payload, rules))
    report.write_csv(results, out_dir / "report.csv")
    p0 = sum(1 for s in results if s.priority == "P0")
    print(f"{out_dir / 'report.md'} and {out_dir / 'report.csv'} written ({p0} P0)")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln-triage",
        description=(
            "Prioritizes Palo Alto and Fortinet vulnerabilities "
            "using KEV, EPSS and exposure."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="Collect vendor advisories, KEV and EPSS")
    p_collect.add_argument(
        "--out",
        type=Path,
        default=Path("data/advisories.json"),
        help="Output file (default: data/advisories.json)",
    )

    p_inv = sub.add_parser("inventory", help="Show inventory devices")
    p_inv.add_argument(
        "--file",
        type=Path,
        default=Path("inventory.example.yaml"),
        help="Inventory file (default: inventory.example.yaml)",
    )
    p_inv.add_argument(
        "--live",
        action="store_true",
        help="Read the actual version from devices that have a 'host'",
    )

    p_match = sub.add_parser("match", help="Which devices are affected by which CVEs")
    p_match.add_argument("--advisories", type=Path, default=Path("data/advisories.json"))
    p_match.add_argument("--inventory", type=Path, default=Path("inventory.example.yaml"))

    p_score = sub.add_parser("score", help="Rank each device/CVE pair from P0 to P3")
    p_score.add_argument("--advisories", type=Path, default=Path("data/advisories.json"))
    p_score.add_argument("--inventory", type=Path, default=Path("inventory.example.yaml"))
    p_score.add_argument("--rules", type=Path, default=Path("rules.yaml"))

    p_report = sub.add_parser("report", help="Write report.md and report.csv")
    p_report.add_argument("--advisories", type=Path, default=Path("data/advisories.json"))
    p_report.add_argument("--inventory", type=Path, default=Path("inventory.example.yaml"))
    p_report.add_argument("--rules", type=Path, default=Path("rules.yaml"))
    p_report.add_argument("--out", type=Path, default=Path("reports"))

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "collect":
        count = collect(args.out)
        print(f"{count} advisories written to {args.out}")
    elif args.command == "inventory":
        _show_inventory(args.file, args.live)
    elif args.command == "match":
        _show_matches(args.advisories, args.inventory)
    elif args.command == "score":
        _show_scores(args.advisories, args.inventory, args.rules)
    elif args.command == "report":
        _write_report(args.advisories, args.inventory, args.rules, args.out)
