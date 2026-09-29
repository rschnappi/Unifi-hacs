"""Diagnose-Download mit Schwärzung sensibler Felder."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .coordinator import UniFiConfigEntry

REDACT = {
    "x_passphrase", "x_iapp_key", "wan_ip", "ip", "mac", "hostname", "serial",
    "gw_mac", "x_authkey", "x_fingerprint", "x_ssh_password", "private_preshared_keys",
    "radius_secret", "x_password", "name",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: UniFiConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    return {
        "entry": {"data": dict(entry.data), "options": dict(entry.options)},
        "counts": {k: len(v) for k, v in asdict(data).items() if isinstance(v, dict)},
        "data": async_redact_data(
            {**asdict(data), "devices": list(data.devices.values()),
             "clients": list(data.clients.values())[:20],
             "users": list(data.users.values())[:20]},
            REDACT,
        ),
    }
