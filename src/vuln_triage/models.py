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