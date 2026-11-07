import json
from datetime import date
from pathlib import Path

from vuln_triage.collectors import paloalto

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_csaf_cve_2026_0322():
    data = json.loads((FIXTURES / "paloalto_CVE-2026-0322.json").read_text())
    adv = paloalto.parse(data)

    assert adv.cve_id == "CVE-2026-0322"
    assert adv.published == date(2026, 10, 14)
    assert adv.cvss == 8.6
    assert adv.vendor_says_exploited is True

    pan_os = [r for r in adv.ranges if r.product == "PAN-OS"]
    assert len(pan_os) == 25
    fixed = {r.version for r in pan_os if r.status == "fixed"}
    affected = {r.version for r in pan_os if r.status == "affected"}
    assert "11.1.4-h37" in fixed
    assert "11.1.0" in affected
    # The 902 trap: same id on "<12.2.4" (affected) and ">=12.2.4" (fixed)
    assert "12.2.4" in fixed and "12.2.4" in affected