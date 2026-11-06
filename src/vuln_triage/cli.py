from __future__ import annotations

import argparse
import logging
from pathlib import Path

from vuln_triage.collect import collect


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

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "collect":
        count = collect(args.out)
        print(f"{count} avis écrits dans {args.out}")
