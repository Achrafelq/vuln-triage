import json
from dataclasses import replace
from pathlib import Path

from vuln_triage import inventory, match, score
from vuln_triage.collect import enrich
from vuln_triage.collectors import epss, fortinet, kev, paloalto

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RULES = score.Rules()


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _records() -> list[dict]:
    """Les vrais avis enregistrés, agrafés avec le KEV et l'EPSS d'exemple."""
    advisories = [paloalto.parse(_load("paloalto_CVE-2026-0322.json"))]
    advisories += fortinet.parse(_load("fortinet_FG-IR-26-182.json"))
    kev_entries = kev.parse(_load("kev_sample.json"))
    epss_scores = epss.parse(_load("epss_sample.json"))
    return enrich(advisories, kev_entries, epss_scores)


def _scored() -> dict[str, score.Scored]:
    devices = inventory.load(ROOT / "inventory.example.yaml")
    results = score.score_all(match.match_all(devices, _records()), devices, RULES)
    return {s.match.device: s for s in results}


def test_example_inventory_priorities():
    scored = _scored()

    assert scored["FW-EDGE-01"].priority == "P0"  # 0322 : KEV + interface d'admin exposée
    assert scored["FW-CORE-01"].priority == "P3"  # CVSS 2.1, rien d'exposé
    assert scored["FW-BRANCH-01"].priority == "P3"
    assert "no fix on this branch: migrate" in scored["FW-BRANCH-01"].reasons


def test_p0_explains_why():
    reasons = _scored()["FW-EDGE-01"].reasons

    assert "in KEV since 2026-10-14" in reasons
    assert "management interface exposed" in reasons


def test_exploited_but_admin_not_exposed_is_p1():
    devices = inventory.load(ROOT / "inventory.example.yaml")
    edge = replace(devices[0], mgmt_exposed=False)
    m = match.match_all([edge], _records())[0]

    assert score.score(m, edge, RULES).priority == "P1"


def _synthetic(epss_value: float | None, cvss: float, exploited: bool = False):
    devices = inventory.load(ROOT / "inventory.example.yaml")
    edge = devices[0]
    m = match.match_all([edge], _records())[0]
    record = dict(m.record, kev=None, vendor_says_exploited=exploited, cvss=cvss)
    record["epss"] = None if epss_value is None else {"epss": epss_value}
    return replace(m, record=record), edge


def test_high_epss_and_exposed_is_p1():
    m, edge = _synthetic(epss_value=0.41, cvss=5.0)
    assert score.score(m, edge, RULES).priority == "P1"


def test_severe_but_not_exploited_is_p2():
    m, edge = _synthetic(epss_value=0.01, cvss=8.6)
    assert score.score(m, edge, RULES).priority == "P2"


def test_rules_file_changes_the_threshold():
    rules = score.load_rules(ROOT / "rules.yaml")
    assert rules.epss_threshold == 0.10

    m, edge = _synthetic(epss_value=0.05, cvss=5.0)
    assert score.score(m, edge, rules).priority == "P3"
    assert score.score(m, edge, score.Rules(epss_threshold=0.04)).priority == "P1"
