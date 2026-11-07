import json
from dataclasses import asdict
from pathlib import Path

import pytest

from vuln_triage import inventory, match
from vuln_triage.collectors import fortinet, paloalto

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def _records() -> list[dict]:
    pa = paloalto.parse(json.loads((FIXTURES / "paloalto_CVE-2026-0322.json").read_text()))
    ft = fortinet.parse(json.loads((FIXTURES / "fortinet_FG-IR-26-182.json").read_text()))
    return [asdict(pa)] + [asdict(a) for a in ft]


def _device(product: str, version: str):
    vendor = "paloalto" if product == "PAN-OS" else "fortinet"
    item = {
        "name": "FW-T",
        "vendor": vendor,
        "version": version,
        "internet_facing": True,
        "mgmt_exposed": True,
        "vpn_portal_enabled": False,
        "auth_portal_enabled": False,
    }
    return inventory.parse({"devices": [item]})[0]


def _verdict(product: str, version: str):
    matches = match.match_all([_device(product, version)], _records())
    if not matches:
        return None
    return matches[0].action, matches[0].fixed_in


def test_example_inventory_gives_the_four_expected_cases():
    devices = inventory.load(ROOT / "inventory.example.yaml")
    matches = match.match_all(devices, _records())
    found = {(m.device, m.cve_id, m.action, m.fixed_in) for m in matches}

    assert found == {
        ("FW-EDGE-01", "CVE-2026-0322", "patch", "11.1.6-h39"),
        ("FW-CORE-01", "CVE-2026-106175", "patch", "7.6.9"),
        ("FW-BRANCH-01", "CVE-2026-106175", "migrate", None),
    }


@pytest.mark.parametrize(
    "version, expected",
    [
        ("11.1.6", ("patch", "11.1.6-h39")),  # bonne maintenance, hotfix manquant
        ("11.1.6-h38", ("patch", "11.1.6-h39")),  # un hotfix trop tôt
        ("11.1.6-h39", None),  # pile le correctif
        ("11.1.8", ("patch", "11.1.10-h35")),  # pas de correctif sur 11.1.8 : le suivant
        ("11.1.16", ("patch", "11.1.16-h3")),
        ("11.1.17", None),  # plus récent que tous les correctifs
        ("12.2.3", ("patch", "12.2.4")),  # le piège 902, côté affecté
        ("12.2.4", None),  # le piège 902, côté corrigé
        ("10.1.14", None),  # branche absente de l'avis
    ],
)
def test_panos_versions(version, expected):
    assert _verdict("PAN-OS", version) == expected


@pytest.mark.parametrize(
    "version, expected",
    [
        ("7.6.3", ("patch", "7.6.9")),
        ("7.6.8", ("patch", "7.6.9")),  # dernière version touchée
        ("7.6.9", None),
        ("7.6.10", None),
        ("7.2.5", ("migrate", None)),  # branche sans correctif
        ("8.0.1", None),  # branche non touchée
    ],
)
def test_fortios_versions(version, expected):
    assert _verdict("FortiOS", version) == expected


def test_unreadable_device_version_is_refused():
    with pytest.raises(ValueError, match="illisible"):
        match.match_all([_device("PAN-OS", "11.1.x")], _records())


def test_parse_version():
    assert match.parse_version("11.1.6-h39") == (11, 1, 6, 39)
    assert match.parse_version("7.4.8") == (7, 4, 8, 0)
    assert match.parse_version("7.4") == (7, 4, 0, 0)
    assert match.parse_version("v7.4.8") is None
