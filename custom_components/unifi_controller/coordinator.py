"""DataUpdateCoordinator: holt alle Controller-Daten in einem Zyklus."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import UniFiApiError, UniFiAuthError, UniFiClient
from .const import (
    CONF_CLIENT_SWITCHES,
    CONF_FIREWALL_POLICIES,
    CONF_PORTFORWARDS,
    CONF_TRAFFICRULES,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

type UniFiConfigEntry = ConfigEntry["UniFiCoordinator"]


@dataclass
class UniFiData:
    """Momentaufnahme des Controllers, jeweils nach Schlüssel indiziert."""

    sysinfo: dict[str, Any] = field(default_factory=dict)
    health: dict[str, dict] = field(default_factory=dict)      # subsystem -> dict
    devices: dict[str, dict] = field(default_factory=dict)     # mac -> dict
    clients: dict[str, dict] = field(default_factory=dict)     # mac -> dict (online)
    users: dict[str, dict] = field(default_factory=dict)       # mac -> dict (bekannt)
    wlans: dict[str, dict] = field(default_factory=dict)       # _id -> dict
    portforwards: dict[str, dict] = field(default_factory=dict)
    trafficrules: dict[str, dict] = field(default_factory=dict)
    firewall_policies: dict[str, dict] = field(default_factory=dict)


def _index(items: list[dict] | None, key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items or []:
        if (k := item.get(key)) is not None:
            out[str(k).lower() if key == "mac" else str(k)] = item
    return out


class UniFiCoordinator(DataUpdateCoordinator[UniFiData]):
    """Pollt Controller; optionale Kategorien laut Optionen."""

    config_entry: UniFiConfigEntry

    def __init__(self, hass: HomeAssistant, entry: UniFiConfigEntry, client: UniFiClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}_{client.host}",
            update_interval=timedelta(
                seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ),
        )
        self.client = client

    async def _async_update_data(self) -> UniFiData:
        opts = self.config_entry.options
        prev = self.data or UniFiData()

        required = {
            "sysinfo": self.client.get_sysinfo(),
            "health": self.client.get_health(),
            "devices": self.client.get_devices(),
            "clients": self.client.get_clients(),
            "wlans": self.client.get_wlans(),
        }
        optional: dict[str, Any] = {}
        if opts.get(CONF_CLIENT_SWITCHES):
            optional["users"] = self.client.get_users()
        if opts.get(CONF_PORTFORWARDS):
            optional["portforwards"] = self.client.get_portforwards()
        if opts.get(CONF_TRAFFICRULES):
            optional["trafficrules"] = self.client.get_trafficrules()
        if opts.get(CONF_FIREWALL_POLICIES):
            optional["firewall_policies"] = self.client.get_firewall_policies()

        keys = list(required) + list(optional)
        results = await asyncio.gather(
            *required.values(), *optional.values(), return_exceptions=True
        )
        raw: dict[str, Any] = {}
        for key, res in zip(keys, results, strict=True):
            if isinstance(res, UniFiAuthError):
                raise ConfigEntryAuthFailed("API-Key abgelehnt") from res
            if isinstance(res, BaseException):
                if key in required:
                    raise UpdateFailed(f"{key}: {res}") from res
                _LOGGER.warning("Optionale Kategorie %s fehlgeschlagen: %s", key, res)
                raw[key] = None
                continue
            raw[key] = res

        def keep(key: str, new: dict[str, dict]) -> dict[str, dict]:
            return getattr(prev, key) if raw.get(key) is None and key in optional else new

        return UniFiData(
            sysinfo=raw["sysinfo"] or {},
            health=_index(raw["health"], "subsystem"),
            devices=_index(raw["devices"], "mac"),
            clients=_index(raw["clients"], "mac"),
            wlans=_index(raw["wlans"], "_id"),
            users=keep("users", _index(raw.get("users"), "mac")),
            portforwards=keep("portforwards", _index(raw.get("portforwards"), "_id")),
            trafficrules=keep("trafficrules", _index(raw.get("trafficrules"), "_id")),
            firewall_policies=keep(
                "firewall_policies", _index(raw.get("firewall_policies"), "_id")
            ),
        )

    async def async_command(self, coro) -> Any:
        """Schreibbefehl ausführen und danach neu laden."""
        try:
            result = await coro
        except UniFiAuthError as err:
            self.config_entry.async_start_reauth(self.hass)
            raise UniFiApiError("API-Key abgelehnt") from err
        await self.async_request_refresh()
        return result
