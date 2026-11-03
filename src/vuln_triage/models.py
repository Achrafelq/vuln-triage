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