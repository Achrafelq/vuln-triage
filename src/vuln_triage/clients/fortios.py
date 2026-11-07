from __future__ import annotations

import requests

STATUS_PATH = "/api/v2/monitor/system/status"


class FortiosError(RuntimeError):
    """Le firewall a répondu, mais pas ce qu'on attendait."""


def fetch_status(host: str, token: str, verify: bool | str = True, timeout: int = 15) -> dict:
    """Demande au firewall son statut. Le token part dans un en-tête, jamais dans l'URL."""
    resp = requests.get(
        f"https://{host}{STATUS_PATH}",
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def parse_status(data: dict) -> dict[str, str]:
    """Extrait nom, modèle et version. FortiOS écrit 'v7.4.8' : on enlève le 'v'."""
    if data.get("status") != "success":
        raise FortiosError(f"réponse en erreur : statut {data.get('status')!r}")
    version = str(data.get("version", "")).strip().lstrip("vV")
    if not version:
        raise FortiosError("réponse sans version")
    results = data.get("results", {})
    model = f"{results.get('model_name', '')} {results.get('model_number', '')}".strip()
    return {"hostname": results.get("hostname", ""), "model": model, "version": version}


def get_version(host: str, token: str, verify: bool | str = True) -> str:
    return parse_status(fetch_status(host, token, verify))["version"]
