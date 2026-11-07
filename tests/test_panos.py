from pathlib import Path

import pytest

from vuln_triage.clients import panos

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_system_info():
    info = panos.parse_system_info((FIXTURES / "panos_system_info.xml").read_text())

    assert info == {"hostname": "FW-LAB-PA", "model": "PA-VM", "version": "11.1.6-h39"}


def test_error_response_is_refused():
    xml = (
        '<response status="error" code="403">'
        "<result><msg>Invalid Credential</msg></result></response>"
    )
    with pytest.raises(panos.PanosError, match="Invalid Credential"):
        panos.parse_system_info(xml)
