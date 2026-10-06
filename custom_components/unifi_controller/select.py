"""Auswahl-Entitäten: Netz je Gerät (Geräteliste mit Netzwechsel)."""
from __future__ import annotations

import time
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .api import UniFiApiError
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, async_add_dynamic

AUTO = "Automatisch (keine Zuordnung)"
RECENT_DAYS = 30


def selectable_networks(coordinator: UniFiCoordinator) -> dict[str, str]:
    """Netz-ID → Name aller LAN-Netze (ohne WAN/VPN), alphabetisch."""
    nets = coordinator.data.config.get("networks", {})
    out = {nid: n.get("name") or nid for nid, n in nets.items()
           if n.get("purpose") in ("corporate", "guest") and n.get("enabled", True)}
    return dict(sorted(out.items(), key=lambda kv: kv[1].lower()))


def device_name(user: dict) -> str:
    return user.get("name") or user.get("hostname") or user.get("mac", "?")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        cutoff = time.time() - RECENT_DAYS * 86400
        online = coordinator.data.clients
        for mac, user in coordinator.data.users.items():
            if mac in online or (user.get("last_seen") or 0) >= cutoff:
                yield ClientNetworkSelect(coordinator, mac)

    async_add_dynamic(coordinator, async_add_entities, factory)


class ClientNetworkSelect(ControllerEntity, SelectEntity):
    """Netz eines Geräts – Auswahl setzt den Netz-Override und verbindet das Gerät neu."""

    _attr_icon = "mdi:lan"

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        user = coordinator.data.users[mac]
        super().__init__(coordinator, f"client_net_{mac}", f"Gerät {device_name(user)} Netz")
        self._mac = mac

    @property
    def _user(self) -> dict | None:
        return self.coordinator.data.users.get(self._mac)

    @property
    def available(self) -> bool:
        return super().available and self._user is not None

    @property
    def options(self) -> list[str]:
        return [AUTO, *selectable_networks(self.coordinator).values()]

    @property
    def current_option(self) -> str | None:
        user = self._user or {}
        if user.get("virtual_network_override_enabled"):
            key = self.coordinator.data.real_id("networks", user.get("virtual_network_override_id"))
            name = selectable_networks(self.coordinator).get(key)
            if name:
                return name
        return AUTO

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        user = self._user or {}
        client = self.coordinator.data.clients.get(self._mac)
        kid = None
        if self.coordinator.kids:
            net = client.get("network_id") if client else user.get("last_connection_network_id")
            kid = next((k.name for k in self.coordinator.kids.kids.values()
                        if net in k.net_ids), None)
        seen = user.get("last_seen")
        return {
            "mac": self._mac,
            "online": client is not None,
            "aktuelles_netz": (client or {}).get("network")
            or user.get("last_connection_network_name"),
            "ip": (client or {}).get("ip") or user.get("last_ip"),
            "feste_ip": user.get("fixed_ip") if user.get("use_fixedip") else None,
            "hersteller": user.get("oui") or None,
            "kind": kid,
            "verbindung": ("LAN" if client.get("is_wired") else f"WLAN {client.get('essid', '')}")
            if client else None,
            "zuletzt_gesehen": dt_util.utc_from_timestamp(seen).isoformat() if seen else None,
        }

    async def async_select_option(self, option: str) -> None:
        if option == AUTO:
            net_id = None
        else:
            net_id = next((nid for nid, name in selectable_networks(self.coordinator).items()
                           if name == option), None)
            if net_id is None:
                raise HomeAssistantError(f"Netz „{option}“ nicht gefunden")
        try:
            await self.coordinator.kids.async_assign_device(self._mac, net_id)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err
