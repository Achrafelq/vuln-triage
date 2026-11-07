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
    op: str  # "<" or ">="
    version: str  # "11.1.4-h37"
    status: str  # "affected" or "fixed"


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
    vendor: str  # "paloalto" or "fortinet"
    product: str  # "PAN-OS" or "FortiOS"
    version: str  # "11.1.6-h39", always a string
    internet_facing: bool  # at least one interface on the Internet
    mgmt_exposed: bool  # management interface reachable from the Internet
    vpn_portal_enabled: bool  # GlobalProtect or SSL-VPN enabled
    auth_portal_enabled: bool  # Authentication Portal / captive portal enabled
    host: str | None = None  # API address, e.g. "192.168.10.1" (optional)
    secret_env: str | None = None  # NAME of the environment variable holding the key
    tls_verify: bool | str = True  # True, False (lab only) or path to the firewall certificate
