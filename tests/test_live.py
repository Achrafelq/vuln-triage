import pytest

from vuln_triage import inventory, live

BASE = {
    "vendor": "paloalto",
    "version": "11.1.6",
    "internet_facing": True,
    "mgmt_exposed": True,
    "vpn_portal_enabled": True,
    "auth_portal_enabled": False,
}


def _devices():
    return inventory.parse(
        {
            "devices": [
                {"name": "FW-API", **BASE, "host": "10.0.0.1", "secret_env": "PA_KEY"},
                {"name": "FW-MANUEL", **BASE},
            ]
        }
    )


def test_refresh_uses_live_version_and_flags_drift():
    fake = {"paloalto": lambda host, secret, verify: "11.1.6-h39"}
    devices, notes = live.refresh(_devices(), env={"PA_KEY": "x"}, clients=fake)

    assert devices[0].version == "11.1.6-h39"
    assert devices[1].version == "11.1.6"
    assert notes == ["FW-API: declared version 11.1.6, actual version 11.1.6-h39"]


def test_refresh_keeps_declared_version_when_unreachable():
    def down(host, secret, verify):
        raise ConnectionError("timeout")

    devices, notes = live.refresh(_devices(), env={"PA_KEY": "x"}, clients={"paloalto": down})

    assert devices[0].version == "11.1.6"
    assert "unreachable" in notes[0]


def test_refresh_without_secret_does_not_call_the_firewall():
    def must_not_run(host, secret, verify):
        raise AssertionError("the firewall should not have been called")

    devices, notes = live.refresh(_devices(), env={}, clients={"paloalto": must_not_run})

    assert devices[0].version == "11.1.6"
    assert "PA_KEY is empty" in notes[0]


def test_secret_in_inventory_is_refused():
    data = {"devices": [{"name": "FW-X", **BASE, "api_key": "LUFRPT1..."}]}
    with pytest.raises(ValueError, match="secret"):
        inventory.parse(data)
