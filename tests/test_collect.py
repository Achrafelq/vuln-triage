from datetime import date

from vuln_triage.collect import enrich
from vuln_triage.models import Advisory, EpssScore, KevEntry


def _advisory(cve_id: str) -> Advisory:
    return Advisory(
        cve_id=cve_id,
        vendor="Palo Alto Networks",
        title="test",
        published=date(2026, 10, 14),
        updated=date(2026, 10, 14),
        cvss=8.6,
        vendor_says_exploited=True,
        description="",
        ranges=(),
    )


def test_enrich_staples_kev_and_epss():
    kev_entries = {
        "CVE-2026-0322": KevEntry(
            cve_id="CVE-2026-0322",
            vendor="Palo Alto Networks",
            product="PAN-OS",
            name="test",
            date_added=date(2026, 10, 14),
            due_date=date(2026, 10, 17),
            ransomware=False,
        )
    }
    epss_scores = {
        "CVE-2026-0322": EpssScore("CVE-2026-0322", 0.0174, 0.77754, date(2026, 11, 3))
    }

    records = enrich(
        [_advisory("CVE-2026-0322"), _advisory("CVE-2026-9999")], kev_entries, epss_scores
    )

    assert records[0]["kev"]["due_date"] == date(2026, 10, 17)
    assert records[0]["epss"]["epss"] == 0.0174
    assert records[1]["kev"] is None
    assert records[1]["epss"] is None
