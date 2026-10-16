"""DataUpdateCoordinator: schnelle Statistik + langsamere Konfiguration."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from functools import cached_property
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
    CONF_CONFIG_INTERVAL,
    CONF_KID_NETWORKS,
    CONF_NEW_CLIENT_NOTIFY,
    CONF_VPN_ENDPOINT,
    DEFAULT_CONFIG_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .resources import (
    DATASETS,
    HYBRID,
    LOCAL_FIELDS,
    OFFICIAL,
    OPTIONAL_DATASETS,
    VOLATILE,
    hybrid_body,
    official_body,
    official_changes,
)

_LOGGER = logging.getLogger(__name__)

MAX_STALE = 3   # so viele Abrufzyklen dürfen Teile ausfallen, bevor Entitäten „nicht verfügbar“ werden

type UniFiConfigEntry = ConfigEntry["UniFiCoordinator"]


@dataclass
class UniFiData:
    """Momentaufnahme des Controllers, jeweils nach Schlüssel indiziert."""

    sysinfo: dict[str, Any] = field(default_factory=dict)
    health: dict[str, dict] = field(default_factory=dict)    # subsystem -> dict
    devices: dict[str, dict] = field(default_factory=dict)   # mac -> dict
    clients: dict[str, dict] = field(default_factory=dict)   # mac -> dict (online)
    config: dict[str, dict[str, dict]] = field(default_factory=dict)  # dataset -> _id -> obj

    @cached_property
    def users(self) -> dict[str, dict]:
        """Bekannte Clients nach MAC (einmal pro Abruf berechnet)."""
        return {
            str(u["mac"]).lower(): u for u in self.config.get("users", {}).values() if u.get("mac")
        }


def _index(items: list[dict] | None, key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items or []:
        if (k := item.get(key)) is not None:
            out[str(k).lower() if key == "mac" else str(k)] = item
    return out


def _link_zones(out: dict[str, dict[str, dict]]) -> None:
    """Offizielle Zonen mit den internen Zonen-IDs verknüpfen (interne Netze kennen nur diese)."""
    by_ext = {z.get("external_id"): z for z in out.get("legacy_zones", {}).values()}
    for zid, zone in out.get("firewall_zones", {}).items():
        if (legacy := by_ext.get(zid)) is not None:
            zone["internal_zone_id"] = legacy.get("_id")
            zone["internal_network_ids"] = legacy.get("network_ids") or []


SPEEDTEST_DAYS = 30


def _merge_speedtests(out: dict[str, dict[str, dict]], prev: dict[str, dict[str, dict]],
                      now_ms: int) -> None:
    """Archiv + letzter Status zu einem Verlauf zusammenführen (Network 11: Archiv leer).

    Der Status liefert nur den jüngsten Test; ältere bleiben aus den vorigen Abrufen erhalten.
    """
    tests = dict(prev.get("speedtests", {}))
    tests.update(out.get("speedtests", {}))
    last = (out.get("speedtest_last") or {}).get("last")
    if last and last.get("rundate"):
        ts = int(last["rundate"]) * 1000
        ok = all(last.get(k) == 2 for k in ("status_download", "status_upload")) \
            if "status_download" in last else True
        tests[str(ts)] = {
            "time": ts, "latency": last.get("latency"),
            "xput_download": last.get("xput_download") if ok else 0,
            "xput_upload": last.get("xput_upload") if ok else 0,
            "interface": last.get("interface_name"),
            "server": (last.get("server") or {}).get("city"),
        }
    cutoff = now_ms - SPEEDTEST_DAYS * 86_400_000
    out["speedtests"] = {k: t for k, t in tests.items() if (t.get("time") or 0) >= cutoff}


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
        self._fast_fail: dict[str, int] = {}
        self.logs: Any = None  # LogManager, wird in __init__.py gesetzt
        self.vpn_endpoint: str = (entry.options.get(CONF_VPN_ENDPOINT) or "").strip()
        from .flows import AppUsage  # noqa: PLC0415
        from .newclients import NewClientWatcher  # noqa: PLC0415

        self.new_clients = NewClientWatcher(
            hass, self, entry.options.get(CONF_NEW_CLIENT_NOTIFY, True))
        self.apps = AppUsage(self, entry.options.get(CONF_KID_NETWORKS))
        self.kids: Any = None  # KidManager, wird in __init__.py gesetzt

    @property
    def datasets(self) -> dict[str, str]:
        # bekannte Geräte werden immer geladen (Geräteliste mit Netzwahl, Kinderprofile)
        with_users = True
        return {
            k: p for k, p in DATASETS.items() if k not in OPTIONAL_DATASETS or with_users
        }

    async def _async_update_data(self) -> UniFiData:
        prev = self.data or UniFiData()
        names = ("sysinfo", "health", "devices", "clients")
        results = await asyncio.gather(
            self.client.get_sysinfo(),
            self.client.get_health(),
            self.client.get_devices(),
            self.client.get_clients(),
            return_exceptions=True,
        )
        fresh: dict[str, Any] = {}
        for name, res in zip(names, results, strict=True):
            if isinstance(res, UniFiAuthError):
                raise ConfigEntryAuthFailed("API-Key abgelehnt") from res
            if isinstance(res, BaseException):
                if not isinstance(res, UniFiApiError):
                    raise res
                # Teilausfall: letzte Daten bis zu MAX_STALE Zyklen weiterverwenden
                streak = self._fast_fail.get(name, 0) + 1
                self._fast_fail[name] = streak
                if self.data is None or streak > MAX_STALE:
                    raise UpdateFailed(str(res)) from res
                _LOGGER.debug("%s nicht abrufbar (%s/%s), verwende letzte Daten: %s",
                              name, streak, MAX_STALE, res)
                fresh[name] = None
                continue
            self._fast_fail.pop(name, None)
            fresh[name] = res
        sysinfo = fresh["sysinfo"] if fresh["sysinfo"] is not None else prev.sysinfo
        health_idx = _index(fresh["health"], "subsystem") if fresh["health"] is not None else prev.health
        devices_idx = _index(fresh["devices"], "mac") if fresh["devices"] is not None else prev.devices
        clients_idx = _index(fresh["clients"], "mac") if fresh["clients"] is not None else prev.clients

        config = prev.config
        now = time.monotonic()
        if self._force_config or now - self._last_config >= self._config_interval:
            config = await self._fetch_config(prev.config)
            self._last_config = now
            self._force_config = False

        data = UniFiData(
            sysinfo=sysinfo or {},
            health=health_idx,
            devices=devices_idx,
            clients=clients_idx,
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
        official = list(OFFICIAL)
        results = await asyncio.gather(
            *(self.client.list_objects(self.datasets[k]) for k in keys),
            *(self.client.integration_list(OFFICIAL[k]) for k in official),
            return_exceptions=True,
        )
        out: dict[str, dict[str, dict]] = {}
        for key, res in zip([*keys, *official], results, strict=True):
            if isinstance(res, UniFiAuthError):
                raise ConfigEntryAuthFailed("API-Key abgelehnt") from res
            if isinstance(res, BaseException):
                if key not in self._failed:
                    _LOGGER.warning("Dataset %s nicht verfügbar: %s", key, res)
                    self._failed.add(key)
                out[key] = prev.get(key, {})
                continue
            self._failed.discard(key)
            if key in OFFICIAL:
                out[key] = {o["id"]: {**o, "_id": o["id"]} for o in res if o.get("id")}
            else:
                out[key] = _index(res, "_id")
        _link_zones(out)
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
            # Network 11 legt Tests nicht mehr im Archiv ab – letzter Test über den Status
            "speedtest_status": self.client.request(
                "POST", "cmd/devmgr", {"cmd": "speedtest-status"}),
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
                elif name == "speedtest_status":
                    pass
                else:
                    out[name] = prev.get(name, {})
                continue
            items = res.get("data", []) if isinstance(res, dict) else res or []
            if name == "wg_users":
                wg.update(_index(items, "_id"))
            elif name == "backups":
                out[name] = {b.get("filename", str(i)): b for i, b in enumerate(items)}
            elif name == "speedtest_status":
                out["speedtest_last"] = {"last": items[0]} if items else {}
            elif name == "speedtests":
                out[name] = {str(t.get("time") or t.get("_id") or i): t
                             for i, t in enumerate(items)}
            else:
                out[name] = _index(items, "_id")
        out["wg_users"] = wg
        _merge_speedtests(out, prev, now)
        from .integration import async_fetch  # noqa: PLC0415

        await async_fetch(self, out, prev)

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

    async def async_update_object(self, dataset: str, obj: dict, changes: dict,
                                  refresh: bool = True) -> Any:
        if dataset in OFFICIAL:
            coro = self.client.integration(
                "PUT", f"{OFFICIAL[dataset]}/{obj['_id']}", official_body(obj, changes))
        elif (mapped := official_changes(dataset, obj, changes)) is not None:
            coro = self._async_hybrid_update(dataset, obj, changes, mapped)
        else:
            body = {k: v for k, v in obj.items()
                    if k not in VOLATILE and k not in LOCAL_FIELDS - {"_id"}} | changes
            coro = self.client.update_object(DATASETS[dataset], obj["_id"], body)
        return await (self.async_command(coro) if refresh else coro)

    async def _async_hybrid_update(self, dataset: str, obj: dict, changes: dict,
                                   mapped: dict) -> Any:
        """Netz/WLAN über die offizielle API ändern; ohne sie (alte Controller) intern."""
        path = f"{HYBRID[dataset]}/{obj['external_id']}"
        try:
            current = await self.client.integration("GET", path)
        except UniFiAuthError:
            raise
        except UniFiApiError as err:
            _LOGGER.debug("%s %s offiziell nicht lesbar (%s) – interne API", dataset,
                          obj.get("name"), err)
            body = {k: v for k, v in obj.items()
                    if k not in VOLATILE and k not in LOCAL_FIELDS - {"_id"}} | changes
            return await self.client.update_object(DATASETS[dataset], obj["_id"], body)
        return await self.client.integration("PUT", path, hybrid_body(current, mapped))

    async def async_create_object(self, dataset: str, body: dict, refresh: bool = True) -> Any:
        coro = (self.client.integration("POST", OFFICIAL[dataset], body)
                if dataset in OFFICIAL else self.client.create_object(DATASETS[dataset], body))
        return await (self.async_command(coro) if refresh else coro)

    async def async_delete_object(self, dataset: str, obj: dict, refresh: bool = True) -> Any:
        coro = (self.client.integration("DELETE", f"{OFFICIAL[dataset]}/{obj['_id']}")
                if dataset in OFFICIAL else self.client.delete_object(DATASETS[dataset], obj["_id"]))
        return await (self.async_command(coro) if refresh else coro)

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
