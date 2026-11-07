from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from vuln_triage import inventory, live, match
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
        print(f"{d.name:<14} {d.product:<8} {d.version:<12} exposé : {', '.join(exposed) or '-'}")
    for note in notes:
        print(f"! {note}")


def _show_matches(advisories_path: Path, inventory_path: Path) -> None:
    payload = json.loads(advisories_path.read_text())
    devices = inventory.load(inventory_path)
    matches = match.match_all(devices, payload["advisories"])
    for m in matches:
        todo = {"patch": f"passer en {m.fixed_in}", "migrate": "changer de branche"}
        what = todo.get(m.action, "aucun correctif publié")
        print(f"{m.device:<14} {m.version:<12} {m.cve_id:<17} {what}")
    print(f"{len(matches)} couple(s) firewall / CVE touché(s)")
    for err in payload.get("errors", []):
        print(f"! collecte incomplète : {err}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln-triage",
        description=(
            "Priorise les vulnérabilités Palo Alto et Fortinet "
            "selon KEV, EPSS et exposition."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="Collecte avis vendeurs, KEV et EPSS")
    p_collect.add_argument(
        "--out",
        type=Path,
        default=Path("data/advisories.json"),
        help="Fichier de sortie (défaut : data/advisories.json)",
    )

    p_inv = sub.add_parser("inventory", help="Affiche les équipements de l'inventaire")
    p_inv.add_argument(
        "--file",
        type=Path,
        default=Path("inventory.example.yaml"),
        help="Fichier d'inventaire (défaut : inventory.example.yaml)",
    )
    p_inv.add_argument(
        "--live",
        action="store_true",
        help="Lit la version réelle sur les équipements qui ont un 'host'",
    )

    p_match = sub.add_parser("match", help="Quels firewalls sont touchés par quelles CVE")
    p_match.add_argument("--advisories", type=Path, default=Path("data/advisories.json"))
    p_match.add_argument("--inventory", type=Path, default=Path("inventory.example.yaml"))

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "collect":
        count = collect(args.out)
        print(f"{count} avis écrits dans {args.out}")
    elif args.command == "inventory":
        _show_inventory(args.file, args.live)
    elif args.command == "match":
        _show_matches(args.advisories, args.inventory)
