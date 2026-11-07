from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import replace

from vuln_triage.clients import fortios, panos
from vuln_triage.models import Device

CLIENTS: dict[str, Callable[..., str]] = {
    "paloalto": panos.get_version,
    "fortinet": fortios.get_version,
}


def refresh(
    devices: list[Device],
    env: Mapping[str, str] = os.environ,
    clients: Mapping[str, Callable[..., str]] = CLIENTS,
) -> tuple[list[Device], list[str]]:
    """Remplace la version déclarée par la version réelle lue sur l'équipement.

    Rien ne bloque : un équipement injoignable garde sa version déclarée,
    et chaque problème est noté dans la liste renvoyée.
    """
    refreshed: list[Device] = []
    notes: list[str] = []
    for dev in devices:
        if dev.host is None:
            refreshed.append(dev)
            continue

        secret = env.get(dev.secret_env or "")
        if not secret:
            notes.append(f"{dev.name}: {dev.secret_env} is empty, keeping declared version")
            refreshed.append(dev)
            continue

        if dev.tls_verify is False:
            notes.append(f"{dev.name}: TLS certificate not verified (lab use only)")

        try:
            live_version = clients[dev.vendor](dev.host, secret, dev.tls_verify)
        except Exception as exc:
            notes.append(f"{dev.name}: unreachable ({exc}), keeping declared version")
            refreshed.append(dev)
            continue

        if live_version != dev.version:
            notes.append(
                f"{dev.name}: declared version {dev.version}, actual version {live_version}"
            )
        refreshed.append(replace(dev, version=live_version))
    return refreshed, notes
