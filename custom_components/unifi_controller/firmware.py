"""Firmware-Updates in Topologie-Reihenfolge.

Warum: Ein Gerät bekommt Strom (PoE) und Netz über sein Uplink-Gerät. Startet der Uplink neu,
während ein nachgelagertes Gerät noch lädt oder flasht, bricht dessen Update ab – im
schlimmsten Fall bleibt es hängen. Deshalb:

* nie zwei Geräte auf demselben Pfad gleichzeitig (Uplink und Gerät dahinter),
* parallel nur bis zu den eingestellten Grenzen: APs und Switches getrennt, je Raum
  höchstens N-1 Switches (mindestens einer bleibt erreichbar, um die anderen zu retten),
  Gateway immer allein,
* von außen nach innen: Blätter zuerst (Mesh-AP, AP am Switch), dann Switches, Gateway zuletzt,
* erst weiter, wenn das Gerät mit neuer Firmware zurück ist UND alle Geräte dahinter wieder
  online sind,
* bei einem Fehler sofort stoppen (das erste Gerät ist der „Kanarienvogel“),
* Geräte auf der Liste „nur manuell“ werden bei Sammel-Updates übersprungen.

Gleichzeitige Einzel-Installationen (z. B. „Alle aktualisieren“ in HA) werden gesammelt und
ebenfalls in Topologie-Reihenfolge nacheinander abgearbeitet.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
import re
import time
from typing import TYPE_CHECKING, Any

from homeassistant.core import callback
from homeassistant.helpers import area_registry as ar, device_registry as dr

from .const import (
    CONF_FW_MANUAL,
    CONF_FW_MAX_AP,
    CONF_FW_MAX_SWITCH,
    CONF_FW_MAX_SWITCH_SITE,
    CONF_FW_SITE_PATTERN,
    DEFAULT_FW_MAX_AP,
    DEFAULT_FW_MAX_SWITCH,
    DEFAULT_FW_MAX_SWITCH_SITE,
    DEFAULT_FW_SITE_PATTERN,
    DOMAIN,
)

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

GATEWAY_TYPES = {"udm", "ugw", "uxg", "uxgpro", "ucg"}
ONLINE = 1
UPGRADING = {4, 5}          # 4 = Upgrade läuft, 5 = Provisionierung
COLLECT_S = 5               # gleichzeitige Installationen so lange sammeln
POLL_S = 15
START_TIMEOUT_S = 240       # so lange darf das Gerät brauchen, um mit dem Update zu beginnen
CHILD_TIMEOUT_S = 420       # nachgelagerte Geräte müssen danach wieder online sein
DEFAULT_UPGRADE_S = 300
DEFAULT_REBOOT_S = 180


def kind(dev: dict) -> str:
    """ap / switch / gateway / other – bestimmt die Gleichzeitigkeits-Grenze."""
    t = (dev.get("type") or "").lower()
    if t in GATEWAY_TYPES:
        return "gateway"
    if t == "uap":
        return "ap"
    if t == "usw":
        return "switch"
    return "other"


def location(dev: dict, pattern: str) -> str:
    """Raum aus dem Gerätenamen (erste Regex-Gruppe), sonst „—“ – nur Rückfall ohne HA-Bereich."""
    try:
        m = re.search(pattern, dev.get("name") or "")
    except re.error:
        m = None
    return (m.group(1) if m and m.groups() else m.group(0) if m else "—").upper()


class FirmwareError(Exception):
    """Update eines Geräts fehlgeschlagen oder nicht möglich."""


def _mac(value: Any) -> str | None:
    return str(value).lower() if value else None


def dev_name(dev: dict | None, mac: str = "") -> str:
    dev = dev or {}
    return dev.get("name") or dev.get("model") or dev.get("mac") or mac


def is_gateway(dev: dict) -> bool:
    return (dev.get("type") or "").lower() in GATEWAY_TYPES


def parent_of(mac: str, devices: dict[str, dict]) -> str | None:
    """Uplink-Gerät (nur wenn es selbst ein UniFi-Gerät dieser Site ist)."""
    dev = devices.get(mac) or {}
    if is_gateway(dev):
        return None
    up = dev.get("uplink") or {}
    for cand in (up.get("uplink_mac"), dev.get("parent_device"),
                 (dev.get("last_uplink") or {}).get("uplink_mac")):
        cand = _mac(cand)
        if cand and cand != mac and cand in devices:
            return cand
    return None


@dataclass
class Node:
    mac: str
    name: str
    parent: str | None
    depth: int
    children: list[str] = field(default_factory=list)
    link: str = ""            # „kabel“, „mesh“, „kabel + PoE“
    gateway: bool = False


def topology(devices: dict[str, dict]) -> dict[str, Node]:
    devices = {_mac(k): v for k, v in devices.items()}
    parents = {m: parent_of(m, devices) for m in devices}
    # Gegenseitige Uplinks (z. B. Core-Switch-Paar ohne UniFi-Gateway) sind keine Hierarchie:
    # alle Geräte eines Zyklus werden zu Wurzeln.
    in_cycle: set[str] = set()
    for start in devices:
        path, cur = [], start
        while cur and cur not in path and cur not in in_cycle:
            path.append(cur)
            cur = parents.get(cur)
        if cur in path:
            in_cycle.update(path[path.index(cur):])
    for mac in in_cycle:
        parents[mac] = None
    nodes: dict[str, Node] = {}
    for mac, dev in devices.items():
        depth, cur, seen = 0, parents[mac], {mac}
        while cur and cur not in seen:   # Zyklen abfangen
            seen.add(cur)
            depth += 1
            cur = parents.get(cur)
        up = dev.get("uplink") or {}
        wireless = (up.get("type") == "wireless") or bool(up.get("is_wireless"))
        link = "mesh" if wireless else "kabel"
        par = devices.get(parents[mac] or "") or {}
        port = up.get("uplink_remote_port")
        if not wireless and port is not None:
            for p in par.get("port_table") or []:
                if p.get("port_idx") == port and p.get("poe_enable"):
                    link = "kabel + PoE"
        if parents[mac] is None:
            link = ("Gateway" if is_gateway(dev) else
                    "Kern (gegenseitiger Uplink)" if mac in in_cycle else "ohne UniFi-Uplink")
        nodes[mac] = Node(mac, dev_name(dev, mac), parents[mac], depth, link=link,
                          gateway=is_gateway(dev))
    for node in nodes.values():
        if node.parent in nodes:
            nodes[node.parent].children.append(node.mac)
    return nodes


def descendants(nodes: dict[str, Node], mac: str) -> list[str]:
    out, stack = [], list(nodes[mac].children) if mac in nodes else []
    while stack:
        m = stack.pop()
        if m in out:
            continue
        out.append(m)
        stack.extend(nodes[m].children)
    return out


def ancestors(nodes: dict[str, Node], mac: str) -> list[str]:
    out, cur = [], nodes[mac].parent if mac in nodes else None
    while cur and cur not in out:
        out.append(cur)
        cur = nodes[cur].parent if cur in nodes else None
    return out


def sort_key(nodes: dict[str, Node], mac: str) -> tuple:
    """Tiefste Geräte zuerst, Gateway ganz zum Schluss."""
    n = nodes.get(mac)
    if n is None:
        return (1, 0, mac)
    return (1 if n.gateway else 0, -n.depth, n.name.lower())


def order(devices: dict[str, dict], macs: list[str] | None = None) -> list[str]:
    nodes = topology(devices)
    macs = [_mac(m) for m in (macs if macs is not None else nodes)]
    return sorted((m for m in macs if m in nodes), key=lambda m: sort_key(nodes, m))


class FirmwareManager:
    """Führt Firmware-Updates eines Controllers in Topologie-Reihenfolge aus – parallel nur
    innerhalb der eingestellten Grenzen."""

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        self.c = coordinator
        self._pending: dict[str, asyncio.Future] = {}
        self._active: dict[str, asyncio.Task] = {}
        self._runner: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self._cancel = False
        self._refresh_lock = asyncio.Lock()
        self._last_refresh = 0.0
        self._area_cache: tuple[float, dict[str, str]] | None = None
        self.status: dict[str, str] = {}      # mac → wartet/läuft/fertig/fehler/abgebrochen
        self.results: list[dict[str, Any]] = []
        self.started: float | None = None

    # ------------------------------------------------------------------ Einstellungen
    @property
    def _opts(self) -> dict[str, Any]:
        return dict(self.c.config_entry.options)

    @property
    def manual(self) -> set[str]:
        return {_mac(m) for m in self._opts.get(CONF_FW_MANUAL) or []}

    @property
    def limits(self) -> dict[str, int]:
        o = self._opts
        return {
            "ap": max(1, int(o.get(CONF_FW_MAX_AP, DEFAULT_FW_MAX_AP))),
            "switch": max(1, int(o.get(CONF_FW_MAX_SWITCH, DEFAULT_FW_MAX_SWITCH))),
            "switch_site": max(1, int(o.get(CONF_FW_MAX_SWITCH_SITE,
                                            DEFAULT_FW_MAX_SWITCH_SITE))),
            "other": 1,
        }

    @property
    def site_pattern(self) -> str:
        return self._opts.get(CONF_FW_SITE_PATTERN) or DEFAULT_FW_SITE_PATTERN

    # ------------------------------------------------------------------ Abfragen
    @property
    def devices(self) -> dict[str, dict]:
        return {_mac(k): v for k, v in (self.c.data.devices if self.c.data else {}).items()}

    @property
    def running(self) -> bool:
        return self._runner is not None and not self._runner.done()

    @property
    def current(self) -> list[str]:
        return list(self._active)

    def busy(self, mac: str) -> bool:
        return self.status.get(_mac(mac)) in ("wartet", "läuft")

    def resolve(self, ident: str) -> str:
        """MAC oder Gerätename → MAC."""
        devs = self.devices
        key = ident.strip().lower()
        if key in devs:
            return key
        hits = [m for m, d in devs.items() if dev_name(d, m).lower() == key]
        if len(hits) == 1:
            return hits[0]
        raise FirmwareError(f"Gerät „{ident}“ nicht gefunden")

    def _areas(self) -> dict[str, str]:
        """MAC → Name des HA-Bereichs (kurz zwischengespeichert, ein Registry-Durchlauf)."""
        now = time.monotonic()
        if self._area_cache is not None and now - self._area_cache[0] < 30:
            return self._area_cache[1]
        out: dict[str, str] = {}
        prefix = f"{self.c.config_entry.entry_id}_"
        try:
            areas = ar.async_get(self.c.hass)
            for entry in dr.async_entries_for_config_entry(
                    dr.async_get(self.c.hass), self.c.config_entry.entry_id):
                if not entry.area_id or not (area := areas.async_get_area(entry.area_id)):
                    continue
                for domain, ident in entry.identifiers:
                    if domain == DOMAIN and ident.startswith(prefix):
                        out[ident.removeprefix(prefix).lower()] = area.name
        except Exception:  # noqa: BLE001 – Registry nicht verfügbar (Tests) → Namen
            out = {}
        self._area_cache = (now, out)
        return out

    def room(self, mac: str, dev: dict | None = None) -> str:
        """Raum = HA-Bereich des Geräts; ohne Bereich aus dem Gerätenamen."""
        if name := self._areas().get(_mac(mac) or ""):
            return name
        return location(dev if dev is not None else self.devices.get(_mac(mac)) or {},
                        self.site_pattern)

    def site_switch_limit(self, devs: dict[str, dict], site: str) -> int:
        """Je Raum: höchstens N-1 Switches gleichzeitig (einer bleibt zum Retten)."""
        n = sum(1 for m, d in devs.items()
                if kind(d) == "switch" and d.get("state") == ONLINE
                and self.room(m, d) == site)
        return min(self.limits["switch_site"], max(1, n - 1))

    def _eligible(self, mac: str, devs: dict[str, dict], nodes: dict[str, Node],
                  pending: set[str], active: set[str]) -> bool:
        """Darf ``mac`` jetzt starten, während ``active`` laufen?"""
        if mac not in nodes:
            return True
        # Pfad-Regel: erst alles dahinter, und nie gleichzeitig mit Uplink/Gerät dahinter
        below = set(descendants(nodes, mac))
        if below & (pending | active) or set(ancestors(nodes, mac)) & active:
            return False
        dev = devs[mac]
        k = kind(dev)
        kinds = [kind(devs[a]) for a in active if a in devs]
        if k == "gateway":
            return not active                     # Gateway immer allein …
        if "gateway" in kinds:
            return False                          # … und nichts neben dem Gateway
        lim = self.limits
        if kinds.count(k) >= lim.get(k, 1):
            return False
        if k == "switch":
            site = self.room(mac, dev)
            same = sum(1 for a in active if a in devs and kind(devs[a]) == "switch"
                       and self.room(a, devs[a]) == site)
            if same >= self.site_switch_limit(devs, site):
                return False
        return True

    def _next(self, devs: dict[str, dict], pending: set[str], active: set[str]) -> list[str]:
        """Geräte, die jetzt (zusätzlich zu ``active``) starten dürfen."""
        nodes = topology(devs)
        started: list[str] = []
        for mac in sorted(pending, key=lambda m: sort_key(nodes, m)):
            if self._eligible(mac, devs, nodes, pending - {mac}, active | set(started)):
                started.append(mac)
        return started

    def plan(self, macs: list[str] | None = None, include_manual: bool = False) -> list[dict]:
        """Ablauf in Wellen (gleich lange Updates angenommen) inkl. Begründungen."""
        devs = self.devices
        nodes = topology(devs)
        explicit = macs is not None
        rows: dict[str, dict] = {}
        for mac in order(devs, macs):
            dev, node = devs[mac], nodes[mac]
            reason = None
            if not dev.get("upgradable"):
                reason = "aktuell"
            elif mac in self.manual and not (include_manual or explicit):
                reason = "nur manuell"
            elif dev.get("state") != ONLINE:
                reason = "offline"
            rows[mac] = {
                "mac": mac, "name": node.name, "model": dev.get("model"), "typ": kind(dev),
                "raum": self.room(mac, dev),
                "version": dev.get("version"), "neu": dev.get("upgrade_to_firmware"),
                "uplink": nodes[node.parent].name if node.parent in nodes else None,
                "verbindung": node.link, "tiefe": node.depth,
                "hinter_diesem_geraet": [nodes[m].name for m in descendants(nodes, mac)],
                "dabei": reason is None, "grund": reason or "wird aktualisiert",
            }
        pending = {m for m, r in rows.items() if r["dabei"]}
        wave = 0
        while pending:
            wave += 1
            batch = self._next(devs, pending, set()) or [min(pending)]
            for m in batch:
                rows[m]["welle"] = wave
            pending -= set(batch)
        return sorted(rows.values(), key=lambda r: (r.get("welle") or 999, r["name"]))

    # ------------------------------------------------------------------ Steuern
    @callback
    def enqueue(self, macs: list[str]) -> dict[str, asyncio.Future]:
        loop = self.c.hass.loop
        futs: dict[str, asyncio.Future] = {}
        for mac in macs:
            mac = _mac(mac)
            if mac in self._pending:
                futs[mac] = self._pending[mac]
                continue
            fut = loop.create_future()
            self._pending[mac] = fut
            self.status[mac] = "wartet"
            futs[mac] = fut
        if not self.running:
            self._cancel = False
            self.results = []
            self.started = time.time()
            self._runner = self.c.config_entry.async_create_background_task(
                self.c.hass, self._run(), f"unifi_firmware_{self.c.config_entry.entry_id}")
        self._wake.set()
        self.c.async_update_listeners()
        return futs

    async def async_install(self, mac: str) -> None:
        """Einzelnes Gerät – wartet, bis es (nach den Regeln) fertig aktualisiert ist."""
        mac = _mac(mac)
        if mac not in self.devices:
            raise FirmwareError("Gerät unbekannt")
        await self.enqueue([mac])[mac]

    @callback
    def cancel(self) -> list[str]:
        """Wartende Updates verwerfen; laufende Geräte werden noch fertig aktualisiert."""
        self._cancel = True
        dropped = [m for m in self._pending if m not in self._active]
        for m in dropped:
            self._fail(m, "abgebrochen")
        self._wake.set()
        return dropped

    def _check_path(self, mac: str) -> None:
        """Kein Update, solange ein Gerät davor oder dahinter (außerhalb von uns) aktualisiert."""
        devs = self.devices
        nodes = topology(devs)
        for other in ancestors(nodes, mac) + descendants(nodes, mac):
            if devs[other].get("state") in UPGRADING:
                raise FirmwareError(
                    f"{nodes[other].name} aktualisiert gerade – {nodes[mac].name} danach starten")

    @callback
    def _fail(self, mac: str, msg: str) -> None:
        self.status[mac] = "abgebrochen" if msg.startswith("abgebrochen") else "fehler"
        fut = self._pending.pop(mac, None)
        if fut and not fut.done():
            fut.set_exception(FirmwareError(msg))
            fut.exception()   # „never retrieved“-Warnung vermeiden, falls niemand wartet

    # ------------------------------------------------------------------ Ablauf
    async def _run(self) -> None:
        await asyncio.sleep(COLLECT_S)
        failed: list[str] = []
        try:
            while self._pending or self._active:
                if not failed and not self._cancel:
                    devs = self.devices
                    waiting = set(self._pending) - set(self._active)
                    for mac in self._next(devs, waiting, set(self._active)):
                        self._start(mac)
                if not self._active:
                    if self._pending and not failed and not self._cancel:
                        # nichts startbar (z. B. Gerät unbekannt) → Rest abbrechen
                        for m in list(self._pending):
                            self._fail(m, "abgebrochen – nicht startbar")
                    break
                self._wake.clear()
                wake = asyncio.ensure_future(self._wake.wait())
                done, _ = await asyncio.wait({*self._active.values(), wake},
                                             return_when=asyncio.FIRST_COMPLETED)
                wake.cancel()
                for mac, task in list(self._active.items()):
                    if task not in done:
                        continue
                    del self._active[mac]
                    err = task.exception()
                    if err is not None:
                        failed.append(f"{dev_name(self.devices.get(mac), mac)}: {err}")
                if failed:
                    for m in [m for m in self._pending if m not in self._active]:
                        self._fail(m, f"abgebrochen, weil {failed[0].split(':')[0]} "
                                      "fehlgeschlagen ist")
        finally:
            self.c.async_update_listeners()
            if self.results:
                await self._notify(failed)

    @callback
    def _start(self, mac: str) -> None:
        self.status[mac] = "läuft"
        self._active[mac] = self.c.hass.async_create_task(self._one(mac), eager_start=False)
        self.c.async_update_listeners()

    async def _one(self, mac: str) -> None:
        devs = self.devices
        name = dev_name(devs.get(mac), mac)
        old = (devs.get(mac) or {}).get("version")
        try:
            new = await self._upgrade(mac)
        except Exception as err:
            if not isinstance(err, FirmwareError):
                _LOGGER.exception("Firmware-Update %s", name)
            self.results.append({"name": name, "von": old, "ergebnis": f"Fehler – {err}"})
            self._fail(mac, str(err))
            raise
        self.status[mac] = "fertig" if new != old else "übersprungen"
        self.results.append({"name": name, "von": old, "auf": new,
                             "ergebnis": "ok" if new != old else "keine neue Firmware"})
        fut = self._pending.pop(mac, None)
        if fut and not fut.done():
            fut.set_result(new)

    async def _refresh(self) -> None:
        """Ein gemeinsamer Abruf für alle parallel laufenden Updates."""
        async with self._refresh_lock:
            if time.monotonic() - self._last_refresh < POLL_S / 2:
                return
            await self.c.async_refresh()
            self._last_refresh = time.monotonic()

    async def _upgrade(self, mac: str) -> str | None:
        dev = self.devices.get(mac)
        if not dev:
            raise FirmwareError("Gerät nicht mehr vorhanden")
        old = dev.get("version")
        if not dev.get("upgradable"):
            return old
        if dev.get("state") != ONLINE:
            raise FirmwareError("Gerät ist nicht online")
        self._check_path(mac)
        nodes = topology(self.devices)
        children = descendants(nodes, mac)
        offline = [nodes[m].name for m in children if self.devices[m].get("state") != ONLINE]
        if offline:
            raise FirmwareError(f"dahinter offline: {', '.join(offline)} – erst prüfen")

        _LOGGER.info("Firmware-Update %s: %s → %s", nodes[mac].name, old,
                     dev.get("upgrade_to_firmware"))
        await self.c.client.devmgr("upgrade", mac)

        limit = (int(dev.get("upgrade_duration") or DEFAULT_UPGRADE_S)
                 + int(dev.get("reboot_duration") or DEFAULT_REBOOT_S) + 300)
        start = time.monotonic()
        went_down = False
        while True:
            await asyncio.sleep(POLL_S)
            await self._refresh()
            d = self.devices.get(mac) or {}
            if not self.c.last_update_success or d.get("state") != ONLINE:
                went_down = True        # Gateway: Controller selbst ist kurz weg
            elif d.get("version") and d.get("version") != old:
                break
            elif went_down and not d.get("upgradable"):
                break
            elapsed = time.monotonic() - start
            if not went_down and elapsed > START_TIMEOUT_S:
                raise FirmwareError("Update hat nicht begonnen")
            if elapsed > limit:
                raise FirmwareError(f"nach {limit // 60} min nicht mit neuer Firmware zurück")

        # alles dahinter (PoE-/Mesh-Geräte) muss wieder da sein, bevor es weitergeht
        start = time.monotonic()
        while True:
            missing = [nodes[m].name for m in children
                       if (self.devices.get(m) or {}).get("state") != ONLINE]
            if not missing:
                break
            if time.monotonic() - start > CHILD_TIMEOUT_S:
                raise FirmwareError(f"danach nicht wieder online: {', '.join(missing)}")
            await asyncio.sleep(POLL_S)
            await self._refresh()
        return (self.devices.get(mac) or {}).get("version")

    async def _notify(self, failed: list[str]) -> None:
        from .notifications import async_send  # noqa: PLC0415

        lines = []
        for r in self.results:
            if r.get("ergebnis") == "ok":
                lines.append(f"✓ {r['name']}: {r['von']} → {r['auf']}")
            else:
                lines.append(f"✗ {r['name']}: {r['ergebnis']}")
        title = "Firmware-Update abgebrochen" if failed else "Firmware-Updates fertig"
        if failed:
            lines.append(f"Gestoppt nach Fehler bei {'; '.join(failed)}. Laufende Geräte wurden "
                         "noch fertig aktualisiert, wartende nicht angefasst.")
        await async_send(self.c.hass, dict(self.c.config_entry.options), "updates", title,
                         "\n".join(lines), {"tag": "unifi_firmware"})
