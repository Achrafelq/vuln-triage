from __future__ import annotations

import requests

STATUS_PATH = "/api/v2/monitor/system/status"


class FortiosError(RuntimeError):
    """The firewall answered, but not with what we expected."""


def fetch_status(host: str, token: str, verify: bool | str = True, timeout: int = 15) -> dict:
    """Ask the firewall for its status. The token goes in a header, never in the URL."""
    resp = requests.get(
        f"https://{host}{STATUS_PATH}",
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def parse_status(data: dict) -> dict[str, str]:
    """Extract hostname, model and version. FortiOS writes 'v7.4.8': strip the 'v'."""
    if data.get("status") != "success":
        raise FortiosError(f"error response: status {data.get('status')!r}")
    version = str(data.get("version", "")).strip().lstrip("vV")
    if not version:
        raise FortiosError("response has no version")
    results = data.get("results", {})
    model = f"{results.get('model_name', '')} {results.get('model_number', '')}".strip()
    return {"hostname": results.get("hostname", ""), "model": model, "version": version}


def get_version(host: str, token: str, verify: bool | str = True) -> str:
    return parse_status(fetch_status(host, token, verify))["version"]
