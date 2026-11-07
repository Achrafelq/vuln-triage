from __future__ import annotations

import xml.etree.ElementTree as ET

import requests

SYSTEM_INFO_CMD = "<show><system><info></info></system></show>"


class PanosError(RuntimeError):
    """Le firewall a répondu, mais pas ce qu'on attendait."""


def fetch_system_info(host: str, api_key: str, verify: bool | str = True, timeout: int = 15) -> str:
    """Demande au firewall 'show system info'. La clé part dans un en-tête, jamais dans l'URL."""
    resp = requests.get(
        f"https://{host}/api/",
        params={"type": "op", "cmd": SYSTEM_INFO_CMD},
        headers={"X-PAN-KEY": api_key},
        verify=verify,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.text


def parse_system_info(xml_text: str) -> dict[str, str]:
    """Extrait nom, modèle et version de la réponse XML."""
    root = ET.fromstring(xml_text)
    if root.get("status") != "success":
        detail = " ".join(t.strip() for t in root.itertext() if t.strip())
        raise PanosError(f"error response: {detail or 'no details'}")
    system = root.find("./result/system")
    if system is None:
        raise PanosError("response has no <system> block")
    version = system.findtext("sw-version", "").strip()
    if not version:
        raise PanosError("response has no <sw-version>")
    return {
        "hostname": system.findtext("hostname", "").strip(),
        "model": system.findtext("model", "").strip(),
        "version": version,
    }


def get_version(host: str, api_key: str, verify: bool | str = True) -> str:
    return parse_system_info(fetch_system_info(host, api_key, verify))["version"]
