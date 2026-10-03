"""Erkennung neuer Geräte im Netz → Event + Benachrichtigung."""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.components import persistent_notification as pn
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import DOMAIN, EVENT_NEW_CLIENT

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

RECENT_S = 86_400   # nur Geräte melden, die UniFi seit < 24 h kennt


class NewClientWatcher:
    """Merkt sich alle je gesehenen MACs; meldet unbekannte (erster Lauf: nur lernen)."""

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator, notify: bool) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.notify = notify
        self._store: Store = Store(
            hass, 1, f"{DOMAIN}.{coordinator.config_entry.entry_id}.known_clients")
        self.known: dict[str, str] = {}
        self._loaded = False
        self.last_new: dict[str, Any] | None = None

    async def async_check(self, clients: dict[str, dict]) -> None:
        users = self.coordinator.data.users if self.coordinator.data else {}
        if not self._loaded:
            stored = await self._store.async_load()
            self._loaded = True
            if stored is None:                       # erster Start: alles lernen
                self.known = {m: c.get("name") or c.get("hostname") or ""
                              for m, c in {**users, **clients}.items()}
                await self._store.async_save(self.known)
                return
            self.known = stored
        # bekannte (auch offline) Clients des Controllers stillschweigend übernehmen
        for m, u in users.items():
            if m not in self.known and not self._recent(u):
                self.known[m] = u.get("name") or u.get("hostname") or ""
        new = [c for m, c in clients.items() if m not in self.known and self._recent(c)]
        for m in [m for m in clients if m not in self.known]:   # ältere Geräte nur lernen
            if not self._recent(clients[m]):
                self.known[m] = clients[m].get("name") or clients[m].get("hostname") or ""
        if not new:
            return
        for c in new:
            mac = str(c.get("mac", "")).lower()
            self.known[mac] = c.get("name") or c.get("hostname") or ""
            info = {
                "mac": mac,
                "name": c.get("name") or c.get("hostname") or c.get("oui") or mac,
                "hostname": c.get("hostname"),
                "vendor": c.get("oui"),
                "ip": c.get("ip"),
                "network": c.get("network"),
                "ssid": c.get("essid"),
                "wired": bool(c.get("is_wired")),
                "ap": c.get("ap_mac") or c.get("sw_mac"),
            }
            self.last_new = info
            self.hass.bus.async_fire(EVENT_NEW_CLIENT, info)
            _LOGGER.info("Neues Gerät im Netz: %s", info)
            if self.notify:
                pn.async_create(
                    self.hass,
                    f"**{info['name']}** ({info['vendor'] or 'unbekannter Hersteller'})\n\n"
                    f"- MAC: `{mac}`\n- IP: {info['ip'] or '–'}\n"
                    f"- Netz: {info['network'] or '–'}"
                    + (f" · WLAN {info['ssid']}" if info["ssid"] else " · LAN") +
                    "\n\nSperren: Dienst `unifi_controller.block_client` mit dieser MAC.",
                    title="Neues Gerät im Netzwerk",
                    notification_id=f"{DOMAIN}_new_{mac.replace(':', '')}",
                )
        await self._store.async_save(self.known)

    @staticmethod
    def _recent(c: dict) -> bool:
        first = c.get("first_seen")
        return not first or time.time() - float(first) < RECENT_S
