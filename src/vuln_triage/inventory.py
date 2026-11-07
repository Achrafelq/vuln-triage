from __future__ import annotations

from pathlib import Path

import yaml

from vuln_triage.models import Device

PRODUCTS = {"paloalto": "PAN-OS", "fortinet": "FortiOS"}
FLAGS = ("internet_facing", "mgmt_exposed", "vpn_portal_enabled", "auth_portal_enabled")
FORBIDDEN = ("api_key", "key", "token", "password", "secret")


def _device(item: dict) -> Device:
    """Vérifie un équipement de l'inventaire et le transforme en Device."""
    name = item.get("name", "<sans nom>")

    for field in FORBIDDEN:
        if field in item:
            raise ValueError(
                f"{name} : '{field}' interdit dans l'inventaire. Ne mets jamais de secret "
                "dans ce fichier : indique le NOM d'une variable d'environnement dans secret_env"
            )

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

    host = item.get("host")
    secret_env = item.get("secret_env")
    if host is not None and not isinstance(secret_env, str):
        raise ValueError(f"{name} : 'host' est renseigné, il faut aussi 'secret_env'")

    tls_verify = item.get("tls_verify", True)
    if not isinstance(tls_verify, bool | str):
        raise ValueError(f"{name} : 'tls_verify' doit être true, false ou un chemin")

    return Device(
        name=name,
        vendor=vendor,
        product=PRODUCTS[vendor],
        version=version,
        internet_facing=item["internet_facing"],
        mgmt_exposed=item["mgmt_exposed"],
        vpn_portal_enabled=item["vpn_portal_enabled"],
        auth_portal_enabled=item["auth_portal_enabled"],
        host=host,
        secret_env=secret_env,
        tls_verify=tls_verify,
    )


def parse(data: dict) -> list[Device]:
    """Transforme le contenu du YAML en liste de Device."""
    return [_device(item) for item in data.get("devices", [])]


def load(path: Path) -> list[Device]:
    """Lit un fichier d'inventaire YAML."""
    return parse(yaml.safe_load(path.read_text()) or {})
