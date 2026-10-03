"""DataUpdateCoordinator: schnelle Statistik + langsamere Konfiguration."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
import logging
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import UniFiApiError, UniFiAuthError, UniFiClient
from .const import (
    CONF_CLIENT_SWITCHES,
    CONF_CONFIG_INTERVAL,
    CONF_KID_NETWORKS,
    CONF_NEW_CLIENT_NOTIFY,
    CONF_VPN_ENDPOINT,
    DEFAULT_CONFIG_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .resources import DATASETS, OPTIONAL_DATASETS, VOLATILE

_LOGGER = logging.getLogger(__name__)

type UniFiConfigEntry = ConfigEntry["UniFiCoordinator"]


@dataclass
class UniFiData:
    """Momentaufnahme des Controllers, jeweils nach Schlüssel indiziert."""

    sysinfo: dict[str, Any] = field(default_factory=dict)
    health: dict[str, dict] = field(default_factory=dict)    # subsystem -> dict
    devices: dict[str, dict] = field(default_factory=dict)   # mac -> dict
    clients: dict[str, dict] = field(default_factory=dict)   # mac -> dict (online)
    config: dict[str, dict[str, dict]] = field(default_factory=dict)  # dataset -> _id -> obj

    @property
    def users(self) -> dict[str, dict]:
        """Bekannte Clients nach MAC."""
        return {
            str(u["mac"]).lower(): u for u in self.config.get("users", {}).values() if u.get("mac")
        }


def _index(items: list[dict] | None, key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items or []:
        if (k := item.get(key)) is not None:
            out[str(k).lower() if key == "mac" else str(k)] = item
    return out


class UniFiCoordinator(DataUpdateCoordinator[UniFiData]):
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
        self._config_interval = entry.options.get(CONF_CONFIG_INTERVAL, DEFAULT_CONFIG_INTERVAL)
        self._last_config = 0.0
        self._force_config = True
        self._failed: set[str] = set()
        self.logs: Any = None  # LogManager, wird in __init__.py gesetzt
        self.vpn_endpoint: str = (entry.options.get(CONF_VPN_ENDPOINT) or "").strip()
        from .flows import AppUsage  # noqa: PLC0415
        from .newclients import NewClientWatcher  # noqa: PLC0415

        self.new_clients = NewClientWatcher(
            hass, self, entry.options.get(CONF_NEW_CLIENT_NOTIFY, True))
        self.apps = AppUsage(self, entry.options.get(CONF_KID_NETWORKS))

    @property
    def datasets(self) -> dict[str, str]:
        with_users = self.config_entry.options.get(CONF_CLIENT_SWITCHES, False)
        return {
            k: p for k, p in DATASETS.items() if k not in OPTIONAL_DATASETS or with_users
        }

    async def _async_update_data(self) -> UniFiData:
        prev = self.data or UniFiData()
        try:
            sysinfo, health, devices, clients = await asyncio.gather(
                self.client.get_sysinfo(),
                self.client.get_health(),
                self.client.get_devices(),
                self.client.get_clients(),
            )
        except UniFiAuthError as err:
            raise ConfigEntryAuthFailed("API-Key abgelehnt") from err
        except UniFiApiError as err:
            raise UpdateFailed(str(err)) from err

        config = prev.config
        now = time.monotonic()
        if self._force_config or now - self._last_config >= self._config_interval:
            config = await self._fetch_config(prev.config)
            self._last_config = now
            self._force_config = False

        data = UniFiData(
            sysinfo=sysinfo or {},
            health=_index(health, "subsystem"),
            devices=_index(devices, "mac"),
            clients=_index(clients, "mac"),
            config=config,
        )
        if self.logs is not None:
            await self.logs.async_poll()
        try:
            await self.new_clients.async_check(data.clients)
            await self.apps.async_poll()
        except Exception:  # noqa: BLE001 – Zusatzfunktionen dürfen den Abruf nie stoppen
            _LOGGER.exception("Zusatzauswertung fehlgeschlagen")
        return data

    async def _fetch_config(self, prev: dict[str, dict[str, dict]]) -> dict[str, dict[str, dict]]:
        keys = list(self.datasets)
        results = await asyncio.gather(
            *(self.client.list_objects(self.datasets[k]) for k in keys), return_exceptions=True
        )
        out: dict[str, dict[str, dict]] = {}
        for key, res in zip(keys, results, strict=True):
            if isinstance(res, UniFiAuthError):
                raise ConfigEntryAuthFailed("API-Key abgelehnt") from res
            if isinstance(res, BaseException):
                if key not in self._failed:
                    _LOGGER.warning("Dataset %s nicht verfügbar: %s", key, res)
                    self._failed.add(key)
                out[key] = prev.get(key, {})
                continue
            self._failed.discard(key)
            out[key] = _index(res, "_id")
        await self._fetch_extras(out, prev)
        return out

    async def _fetch_extras(self, out: dict[str, dict[str, dict]],
                            prev: dict[str, dict[str, dict]]) -> None:
        """WireGuard-Zugänge, Speedtest-Verlauf, Controller-Backups (best effort)."""
        servers = [nid for nid, n in out.get("networks", {}).items()
                   if n.get("vpn_type") == "wireguard-server"]
        now = int(time.time() * 1000)
        jobs = {
            **{f"wg:{nid}": self.client.request("GET", f"v2/wireguard/{nid}/users")
               for nid in servers},
            "speedtests": self.client.request("POST", "stat/report/archive.speedtest", {
                "attrs": ["xput_download", "xput_upload", "latency", "time"],
                "start": now - 30 * 86_400_000, "end": now}),
            "backups": self.client.request("POST", "cmd/backup", {"cmd": "list-backups"}),
        }
        results = await asyncio.gather(*jobs.values(), return_exceptions=True)
        wg: dict[str, dict] = {}
        for key, res in zip(jobs, results, strict=True):
            name = "wg_users" if key.startswith("wg:") else key
            if isinstance(res, BaseException):
                if name not in self._failed:
                    _LOGGER.debug("Zusatzdaten %s nicht verfügbar: %s", name, res)
                    self._failed.add(name)
                if name == "wg_users":
                    wg.update(prev.get("wg_users", {}))
                else:
                    out[name] = prev.get(name, {})
                continue
            items = res.get("data", []) if isinstance(res, dict) else res or []
            if name == "wg_users":
                wg.update(_index(items, "_id"))
            elif name == "backups":
                out[name] = {b.get("filename", str(i)): b for i, b in enumerate(items)}
            else:
                out[name] = _index(items, "_id")
        out["wg_users"] = wg

    def find(self, dataset: str, ident: str) -> dict:
        """Objekt per _id oder eindeutigem Namen finden."""
        from .resources import object_name  # noqa: PLC0415

        objs = (self.data.config if self.data else {}).get(dataset, {})
        if ident in objs:
            return objs[ident]
        hits = [o for o in objs.values() if object_name(o).lower() == ident.strip().lower()]
        if len(hits) == 1:
            return hits[0]
        raise UniFiApiError(
            f"{dataset}: '{ident}' " + ("mehrdeutig" if hits else "nicht gefunden")
        )

    async def async_update_object(self, dataset: str, obj: dict, changes: dict) -> Any:
        body = {k: v for k, v in obj.items() if k not in VOLATILE} | changes
        return await self.async_command(
            self.client.update_object(DATASETS[dataset], obj["_id"], body)
        )

    async def async_command(self, coro) -> Any:
        """Schreibbefehl ausführen und danach sofort alles neu laden."""
        try:
            result = await coro
        except UniFiAuthError as err:
            self.config_entry.async_start_reauth(self.hass)
            raise UniFiApiError("API-Key abgelehnt") from err
        self._force_config = True
        await self.async_refresh()
        return result
