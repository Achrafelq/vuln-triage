import json
from pathlib import Path

from vuln_triage.collectors import fortinet

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_fortinet_fg_ir_26_182():
    data = json.loads((FIXTURES / "fortinet_FG-IR-26-182.json").read_text())
    advisories = fortinet.parse(data)

    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.cve_id == "CVE-2026-106175"
    assert adv.vendor == "Fortinet"
    assert adv.cvss == 2.1
    assert adv.vendor_says_exploited is False

    fortios = {(r.op, r.version, r.status) for r in adv.ranges if r.product == "FortiOS"}
    assert (">=", "7.6.0", "affected") in fortios
    assert ("<=", "7.6.8", "affected") in fortios
    assert ("~", "7.4", "affected") in fortios
    assert ("~", "8.0", "not_affected") in fortios
    assert (">=", "7.6.9", "fixed") in fortios
    assert ("~", "7.4", "migrate") in fortios


def test_clean_handles_dirty_strings():
    assert fortinet._clean("FortiOS/ 8.0 all versions") == ("FortiOS", "8.0 all versions")
    assert fortinet._clean("FortiOS-upcoming  7.6.9") == ("FortiOS", "7.6.9")

def test_exploited_flag_from_rss_text():
    data = json.loads((FIXTURES / "fortinet_FG-IR-26-175.json").read_text())
    rss = "This has been reported to be exploited in the wild."
    adv = fortinet.parse(data, rss)[0]

    assert adv.cve_id == "CVE-2026-104286"
    assert adv.vendor_says_exploited is True


def test_says_exploited_ignores_negation():
    assert fortinet._says_exploited("reported to be exploited in the wild")
    assert not fortinet._says_exploited("has not been exploited in the wild")
    assert not fortinet._says_exploited("Fortinet is not aware of exploitation")