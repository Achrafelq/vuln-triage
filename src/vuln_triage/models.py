from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: date
    due_date: date
    ransomware: bool



@dataclass(frozen=True)
class EpssScore:
    cve_id: str
    epss: float
    percentile: float
    date: date



@dataclass(frozen=True)
class VersionRange:
    product: str  # "PAN-OS"
    op: str  # "<" ou ">="
    version: str  # "11.1.4-h37"
    status: str  # "affected" ou "fixed"


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    vendor: str
    title: str
    published: date
    updated: date
    cvss: float | None
    vendor_says_exploited: bool
    description: str
    ranges: tuple[VersionRange, ...]



@dataclass(frozen=True)
class Device:
    name: str  # "FW-TLS-01"
    vendor: str  # "paloalto" ou "fortinet"
    product: str  # "PAN-OS" ou "FortiOS"
    version: str  # "11.1.6-h39", toujours du texte
    internet_facing: bool  # a au moins une interface sur Internet
    mgmt_exposed: bool  # interface d'administration joignable depuis Internet
    vpn_portal_enabled: bool  # GlobalProtect ou SSL-VPN actif
    auth_portal_enabled: bool  # Authentication Portal / captive portal actif
    host: str | None = None  # adresse de l'API, ex. "192.168.10.1" (optionnel)
    secret_env: str | None = None  # NOM de la variable d'environnement qui contient la clé
    tls_verify: bool | str = True  # True, False (lab) ou chemin vers le certificat du firewall
