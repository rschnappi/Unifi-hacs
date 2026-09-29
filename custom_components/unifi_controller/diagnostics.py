"""Diagnose-Download mit Schwärzung sensibler Felder."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .coordinator import UniFiConfigEntry
from .resources import redact

REDACT = {"wan_ip", "ip", "mac", "hostname", "serial", "gw_mac", "name", "ips"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: UniFiConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    data = coordinator.data
    return {
        "entry": {"data": dict(entry.data), "options": dict(entry.options)},
        "counts": {
            "devices": len(data.devices),
            "clients": len(data.clients),
            **{k: len(v) for k, v in data.config.items()},
        },
        "failed_datasets": sorted(coordinator._failed),  # noqa: SLF001
        "data": async_redact_data(
            redact({
                "sysinfo": data.sysinfo,
                "health": data.health,
                "devices": list(data.devices.values()),
                "clients": list(data.clients.values())[:20],
                "config": {k: list(v.values())[:10] for k, v in data.config.items()},
            }),
            REDACT,
        ),
    }
