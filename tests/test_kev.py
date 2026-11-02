import json
from datetime import date
from pathlib import Path

from vuln_triage.collectors import kev

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_kev_sample():
    data = json.loads((FIXTURES / "kev_sample.json").read_text())
    entries = kev.parse(data)

    assert len(entries) == 2
    pan = entries["CVE-2026-0322"]
    assert pan.vendor == "Palo Alto Networks"
    assert pan.date_added == date(2026, 10, 14)
    assert (pan.due_date - pan.date_added).days == 3
    assert entries["CVE-2021-44228"].ransomware is True