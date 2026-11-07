import csv
import json
from pathlib import Path

from vuln_triage import inventory, match, report, score
from vuln_triage.collect import enrich
from vuln_triage.collectors import epss, fortinet, kev, paloalto

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RULES = score.Rules()


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _setup(errors: list[str] | None = None):
    advisories = [paloalto.parse(_load("paloalto_CVE-2026-0322.json"))]
    advisories += fortinet.parse(_load("fortinet_FG-IR-26-182.json"))
    kev_entries = kev.parse(_load("kev_sample.json"))
    records = enrich(advisories, kev_entries, epss.parse(_load("epss_sample.json")))
    payload = {
        "generated_at": "2026-11-07T16:00:00+00:00",
        "count": len(records),
        "errors": errors or [],
        "advisories": records,
    }
    devices = inventory.load(ROOT / "inventory.example.yaml")
    scored = score.score_all(match.match_all(devices, records), devices, RULES)
    return scored, devices, payload


def test_summary_names_the_urgent_action():
    scored, devices, payload = _setup()
    md = report.render_markdown(scored, devices, payload, RULES)

    assert md.startswith("# vuln-triage report — 2026-11-07")
    assert "- **1 urgent action(s) (P0)**:" in md
    assert "  - FW-EDGE-01: CVE-2026-0322, upgrade to 11.1.6-h39" in md
    assert "Warning: incomplete collection" not in md


def test_upgrade_plan_checks_what_the_target_really_fixes():
    scored, devices, _ = _setup()
    plan = {p["device"]: p for p in report.upgrade_plan(scored, devices)}

    assert plan["FW-EDGE-01"]["target"] == "11.1.6-h39"
    assert plan["FW-EDGE-01"]["fixes"] == 1
    assert plan["FW-CORE-01"]["target"] == "7.6.9"
    assert "FW-BRANCH-01" not in plan  # nothing to patch: must migrate


def test_incomplete_collection_is_shown_at_the_top():
    scored, devices, payload = _setup(errors=["Fortinet: RSS index unreachable (500)"])
    md = report.render_markdown(scored, devices, payload, RULES)
    summary = md.split("## Recommended upgrades")[0]

    assert "Warning: incomplete collection (1 source error(s))" in summary
    assert "- Fortinet: RSS index unreachable (500)" in md


def test_csv_has_one_row_per_pair(tmp_path):
    scored, _, _ = _setup()
    path = tmp_path / "report.csv"
    report.write_csv(scored, path)
    rows = list(csv.DictReader(path.open()))

    assert len(rows) == len(scored)
    assert rows[0]["priority"] == "P0"
    assert rows[0]["kev_date_added"] == "2026-10-14"
