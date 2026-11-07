from pathlib import Path

import pytest

from vuln_triage import inventory

EXAMPLE = Path(__file__).parent.parent / "inventory.example.yaml"


def test_load_example_inventory():
    devices = inventory.load(EXAMPLE)

    assert [d.name for d in devices] == ["FW-EDGE-01", "FW-EDGE-02", "FW-CORE-01", "FW-BRANCH-01"]
    edge = devices[0]
    assert edge.product == "PAN-OS"
    assert edge.version == "11.1.6"
    assert edge.mgmt_exposed is True


def test_version_without_quotes_is_refused():
    data = {"devices": [{"name": "FW-X", "vendor": "fortinet", "version": 7.10}]}
    with pytest.raises(ValueError, match="quoted"):
        inventory.parse(data)


def test_missing_flag_is_refused():
    data = {"devices": [{"name": "FW-X", "vendor": "fortinet", "version": "7.4.8"}]}
    with pytest.raises(ValueError, match="internet_facing"):
        inventory.parse(data)