from __future__ import annotations

from pathlib import Path

import yaml

from vuln_triage.models import Device

PRODUCTS = {"paloalto": "PAN-OS", "fortinet": "FortiOS"}
FLAGS = ("internet_facing", "mgmt_exposed", "vpn_portal_enabled", "auth_portal_enabled")


def _device(item: dict) -> Device:
    """Vérifie un équipement de l'inventaire et le transforme en Device."""
    name = item.get("name", "<sans nom>")

    vendor = item.get("vendor")
    if vendor not in PRODUCTS:
        raise ValueError(
            f"{name} : vendeur '{vendor}' inconnu (attendu : paloalto ou fortinet)"
        )

    version = item.get("version")
    if not isinstance(version, str):
        raise ValueError(
            f'{name} : version {version!r} à mettre entre guillemets, ex. "7.4.8"'
        )

    for flag in FLAGS:
        if not isinstance(item.get(flag), bool):
            raise ValueError(f"{name} : '{flag}' manquant ou différent de true/false")

    return Device(
        name=name,
        vendor=vendor,
        product=PRODUCTS[vendor],
        version=version,
        internet_facing=item["internet_facing"],
        mgmt_exposed=item["mgmt_exposed"],
        vpn_portal_enabled=item["vpn_portal_enabled"],
        auth_portal_enabled=item["auth_portal_enabled"],
    )


def parse(data: dict) -> list[Device]:
    """Transforme le contenu du YAML en liste de Device."""
    return [_device(item) for item in data.get("devices", [])]


def load(path: Path) -> list[Device]:
    """Lit un fichier d'inventaire YAML."""
    return parse(yaml.safe_load(path.read_text()) or {})