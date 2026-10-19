"""Firmware-Updates in Topologie-Reihenfolge.

Warum: Ein Gerät bekommt Strom (PoE) und Netz über sein Uplink-Gerät. Startet der Uplink neu,
während ein nachgelagertes Gerät noch lädt oder flasht, bricht dessen Update ab – im
schlimmsten Fall bleibt es hängen. Deshalb:

* immer nur EIN Gerät gleichzeitig,
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
import time
from typing import TYPE_CHECKING, Any

from homeassistant.core import callback

from .const import CONF_FW_MANUAL

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
    """Serialisiert Firmware-Updates eines Controllers in Topologie-Reihenfolge."""

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        self.c = coordinator
        self._pending: dict[str, asyncio.Future] = {}
        self._runner: asyncio.Task | None = None
        self._cancel = False
        self.current: str | None = None
        self.status: dict[str, str] = {}      # mac → wartet/läuft/fertig/fehler/übersprungen
        self.results: list[dict[str, Any]] = []
        self.started: float | None = None

    # ------------------------------------------------------------------ Abfragen
    @property
    def devices(self) -> dict[str, dict]:
        return {_mac(k): v for k, v in (self.c.data.devices if self.c.data else {}).items()}

    @property
    def manual(self) -> set[str]:
        return {_mac(m) for m in self.c.config_entry.options.get(CONF_FW_MANUAL) or []}

    @property
    def running(self) -> bool:
        return self._runner is not None and not self._runner.done()

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

    def plan(self, macs: list[str] | None = None, include_manual: bool = False) -> list[dict]:
        """Reihenfolge inkl. Begründung, warum ein Gerät (nicht) dabei ist."""
        devs = self.devices
        nodes = topology(devs)
        explicit = macs is not None
        rows: list[dict] = []
        for mac in order(devs, macs):
            dev, node = devs[mac], nodes[mac]
            reason = None
            if not dev.get("upgradable"):
                reason = "aktuell"
            elif mac in self.manual and not (include_manual or explicit):
                reason = "nur manuell"
            elif dev.get("state") != ONLINE:
                reason = "offline"
            rows.append({
                "mac": mac, "name": node.name, "model": dev.get("model"),
                "version": dev.get("version"), "neu": dev.get("upgrade_to_firmware"),
                "uplink": nodes[node.parent].name if node.parent in nodes else None,
                "verbindung": node.link, "tiefe": node.depth,
                "hinter_diesem_geraet": [nodes[m].name for m in descendants(nodes, mac)],
                "dabei": reason is None, "grund": reason or "wird aktualisiert",
            })
        pos = 0
        for row in rows:
            if row["dabei"]:
                pos += 1
                row["schritt"] = pos
        return rows

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
        self.c.async_update_listeners()
        return futs

    async def async_install(self, mac: str) -> None:
        """Einzelnes Gerät – wartet, bis es (in Topologie-Reihenfolge) fertig ist."""
        mac = _mac(mac)
        self._check_path(mac)
        await self.enqueue([mac])[mac]

    @callback
    def cancel(self) -> list[str]:
        """Wartende Updates verwerfen; ein laufendes Gerät wird noch fertig aktualisiert."""
        self._cancel = True
        dropped = [m for m in self._pending if m != self.current]
        for m in dropped:
            self._fail(m, "abgebrochen")
        return dropped

    def _check_path(self, mac: str) -> None:
        """Kein Update, solange ein Gerät davor oder dahinter gerade aktualisiert."""
        devs = self.devices
        if mac not in devs:
            raise FirmwareError("Gerät unbekannt")
        nodes = topology(devs)
        for other in ancestors(nodes, mac) + descendants(nodes, mac):
            if devs[other].get("state") in UPGRADING and other != self.current:
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
        failed: str | None = None
        try:
            while self._pending and not self._cancel:
                devs = self.devices
                nodes = topology(devs)
                mac = min(self._pending, key=lambda m: sort_key(nodes, m))
                self.current = mac
                self.status[mac] = "läuft"
                self.c.async_update_listeners()
                name = dev_name(devs.get(mac), mac)
                old = (devs.get(mac) or {}).get("version")
                try:
                    new = await self._upgrade(mac)
                except FirmwareError as err:
                    failed = f"{name}: {err}"
                    self.results.append({"name": name, "von": old, "ergebnis": f"Fehler – {err}"})
                    self._fail(mac, str(err))
                    for other in list(self._pending):
                        self._fail(other, f"abgebrochen, weil {name} fehlgeschlagen ist")
                    break
                except Exception as err:  # noqa: BLE001
                    _LOGGER.exception("Firmware-Update %s", name)
                    failed = f"{name}: {err}"
                    self._fail(mac, str(err))
                    for other in list(self._pending):
                        self._fail(other, f"abgebrochen, weil {name} fehlgeschlagen ist")
                    break
                self.status[mac] = "fertig" if new != old else "übersprungen"
                self.results.append({"name": name, "von": old, "auf": new,
                                     "ergebnis": "ok" if new != old else "keine neue Firmware"})
                fut = self._pending.pop(mac, None)
                if fut and not fut.done():
                    fut.set_result(new)
        finally:
            self.current = None
            self.c.async_update_listeners()
            if self.results:
                await self._notify(failed)

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
            await self.c.async_refresh()
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
            await self.c.async_refresh()
        return (self.devices.get(mac) or {}).get("version")

    async def _notify(self, failed: str | None) -> None:
        from .notifications import async_send  # noqa: PLC0415

        lines = []
        for r in self.results:
            if r.get("ergebnis") == "ok":
                lines.append(f"✓ {r['name']}: {r['von']} → {r['auf']}")
            else:
                lines.append(f"✗ {r['name']}: {r['ergebnis']}")
        title = "Firmware-Update abgebrochen" if failed else "Firmware-Updates fertig"
        if failed:
            lines.append(f"Gestoppt bei {failed}. Restliche Geräte wurden nicht angefasst.")
        await async_send(self.c.hass, dict(self.c.config_entry.options), "updates", title,
                         "\n".join(lines), {"tag": "unifi_firmware"})
