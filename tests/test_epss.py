import json
from pathlib import Path

from vuln_triage.collectors import epss

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_epss_sample():
    data = json.loads((FIXTURES / "epss_sample.json").read_text())
    scores = epss.parse(data)

    assert len(scores) == 2
    assert scores["CVE-2021-44228"].epss > 0.9
    assert scores["CVE-2026-0322"].epss < 0.1
    assert scores["CVE-2026-0322"].percentile > 0.9


def test_chunks_splits_in_batches_of_100():
    ids = [f"CVE-2026-{i:05d}" for i in range(250)]
    batches = epss.chunks(ids, 100)

    assert [len(b) for b in batches] == [100, 100, 50]
    assert batches[0][0] == "CVE-2026-00000"
    assert batches[-1][-1] == "CVE-2026-00249"