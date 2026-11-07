import json
from pathlib import Path

import pytest

from vuln_triage.clients import fortios

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_status_strips_v():
    data = json.loads((FIXTURES / "fortios_system_status.json").read_text())
    info = fortios.parse_status(data)

    assert info["version"] == "7.4.8"
    assert info["hostname"] == "FW-LAB-FG"
    assert info["model"] == "FortiGate VM64"


def test_error_response_is_refused():
    with pytest.raises(fortios.FortiosError):
        fortios.parse_status({"status": "error", "http_status": 401})
