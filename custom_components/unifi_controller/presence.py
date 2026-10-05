"""Anwesenheitserkennung: Personen (Config-Subentry „person“) aus ihren WLAN/LAN-Geräten.

Pro Gerät (MAC) wird verfolgt, ob es verbunden ist, wann es zuletzt gesehen wurde und an
welchem AP/Switch es hing. Daraus entsteht pro Person:

  * Ankommen sofort – ein Gerät taucht in der Client-Liste auf (oder ein Connect-Event kommt).
  * Gehen verzögert und abgestuft:
      - letzte Verbindung an einem „Ausgangs-AP“ (z. B. Vorraum)  → kurze Frist (exit_delay)
      - sonst (Handy schläft im Haus, WLAN im Doze)               → lange Frist (away_delay)
  * Fusion: abwesend erst, wenn alle Geräte über ihrer Frist sind UND keine Zusatzquelle
    (device_tracker = home, binary_sensor = on) Anwesenheit meldet.

Die Fristen gelten auch für die device_tracker der Geräte – an eine HA-Person gehängt,
bekommt diese dieselbe entprellte Anwesenheit.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigSubentry
from homeassistant.const import STATE_HOME, STATE_ON
from homeassistant.core import Context, Event, HomeAssistant, callback
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.util import dt as dt_util

from .const import DEFAULT_SCAN_INTERVAL, DOMAIN, EVENT_PRESENCE

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

SUBENTRY_PERSON = "person"
CONF_NAME = "name"
CONF_DEVICES = "devices"
CONF_EXIT_APS = "exit_aps"
CONF_EXIT_DELAY = "exit_delay"      # min
CONF_AWAY_DELAY = "away_delay"      # min
CONF_SOURCES = "sources"

DEFAULT_EXIT_DELAY = 3
DEFAULT_AWAY_DELAY = 15

STALE_MIN_S = 180          # Eintrag in der Client-Liste älter → gilt als nicht mehr verbunden
ROTATION_DAYS = 3          # private MAC so lange ungesehen + Nachfolger mit gleichem Hostnamen
ROTATION_CHECK_S = 3600
AWAY = "Abwesend"


def is_private_mac(mac: str) -> bool:
    """Locally-administered-Bit gesetzt (zufällige/private MAC von Android/iOS/Windows)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@dataclass
class DeviceState:
    """Beobachteter Zustand eines Geräts (gemeinsam für alle Personen)."""

    mac: str
    name: str = ""
    hostname: str | None = None
    ip: str | None = None
    connected: bool = False
    last_seen: float = 0.0          # Unix-Zeit (s)
    uplink: str | None = None       # MAC des AP/Switch der aktuellen/letzten Verbindung
    left_uplink: str | None = None  # wo die Verbindung zuletzt endete
    left_by_event: bool = False
    ssid: str | None = None
    signal: int | None = None
    wired: bool = False
    known: bool = False             # dem Controller bekannt


class Person:
    """Eine Person mit ihren Geräten, Fristen und Zusatzquellen."""

    def __init__(self, manager: PresenceManager, subentry: ConfigSubentry) -> None:
        self.manager = manager
        self.subentry_id = subentry.subentry_id
        d = subentry.data
        self.name: str = d[CONF_NAME]
        self.macs: list[str] = [str(m).lower() for m in d.get(CONF_DEVICES) or []]
        self.exit_aps: set[str] = {str(m).lower() for m in d.get(CONF_EXIT_APS) or []}
        self.exit_delay = int(d.get(CONF_EXIT_DELAY, DEFAULT_EXIT_DELAY)) * 60
        self.away_delay = int(d.get(CONF_AWAY_DELAY, DEFAULT_AWAY_DELAY)) * 60
        self.sources: list[str] = list(d.get(CONF_SOURCES) or [])
        self.present: bool | None = None
        self.since: datetime | None = None
        self.reason: str = ""
        self.trigger: str | None = None      # Gerät/Quelle, die zuletzt entschieden hat
        self.listeners: list[Callable[[], None]] = []

    # ------------------------------------------------------------ Bewertung
    def delay_for(self, ds: DeviceState) -> int:
        return self.exit_delay if ds.left_uplink and ds.left_uplink in self.exit_aps \
            else self.away_delay

    def device_present(self, mac: str, now: float) -> tuple[bool, str]:
        ds = self.manager.devices.get(mac)
        if ds is None or not ds.known:
            return False, "dem Controller unbekannt"
        if ds.connected:
            return True, f"verbunden über {self.manager.uplink_name(ds.uplink)}"
        if not ds.last_seen:
            return False, "nie gesehen"
        age = now - ds.last_seen
        delay = self.delay_for(ds)
        where = self.manager.uplink_name(ds.left_uplink)
        kind = "Ausgang" if delay == self.exit_delay and self.exit_aps else "im Haus"
        if age < delay:
            return True, (f"getrennt an {where} ({kind}) vor {int(age // 60)} min, "
                          f"Frist {delay // 60} min")
        return False, f"zuletzt an {where} vor {int(age // 60)} min"

    def source_states(self) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for eid in self.sources:
            st = self.manager.hass.states.get(eid)
            if st is not None:
                out[eid] = st.state in (STATE_HOME, STATE_ON)
        return out

    def evaluate(self, now: float, initial: bool = False) -> None:
        dev = {m: self.device_present(m, now) for m in self.macs}
        src = self.source_states()
        hits = [m for m, (p, _) in dev.items() if p]
        src_hits = [e for e, p in src.items() if p]
        present = bool(hits or src_hits)
        if hits:
            # verbundene Geräte vor „in der Frist“
            best = next((m for m in hits if self.manager.devices[m].connected), hits[0])
            reason, trig = dev[best][1], self.manager.devices[best].name or best
        elif src_hits:
            reason, trig = "laut Zusatzquelle", src_hits[0]
        else:
            reason = "; ".join(f"{self.manager.devices[m].name or m}: {r}"
                               for m, (_, r) in dev.items() if m in self.manager.devices) \
                or "keine Geräte"
            trig = None
        changed = present != self.present
        self.reason = reason
        if changed:
            old = self.present
            self.present = present
            self.since = dt_util.utcnow()
            self.trigger = trig
            if old is not None and not initial:
                self.manager.async_announce(self, present, trig, reason)
        self._notify()

    # ------------------------------------------------------------ Raum
    def room(self) -> str:
        if not self.present:
            return AWAY
        cands = [self.manager.devices[m] for m in self.macs
                 if m in self.manager.devices and self.manager.devices[m].uplink]
        if not cands:
            return "Zuhause"
        # verbundene WLAN-Geräte zuerst (Handy wandert mit), dann zuletzt gesehen
        best = max(cands, key=lambda d: (d.connected, not d.wired, d.last_seen))
        return self.manager.uplink_room(best.uplink)

    def device_attrs(self, now: float) -> list[dict[str, Any]]:
        out = []
        for m in self.macs:
            ds = self.manager.devices.get(m)
            present, why = self.device_present(m, now)
            out.append({
                "mac": m, "name": ds.name if ds else m, "anwesend": present,
                "verbunden": bool(ds and ds.connected), "grund": why,
                "zuletzt": dt_util.utc_from_timestamp(ds.last_seen).isoformat()
                if ds and ds.last_seen else None,
                "private_mac": is_private_mac(m),
            })
        return out

    def _notify(self) -> None:
        for cb in list(self.listeners):
            cb()


class PresenceManager:
    """Alle Personen einer Config-Entry + gemeinsamer Geräte-Zustand."""

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.persons: dict[str, Person] = {}
        self.devices: dict[str, DeviceState] = {}
        self._unsubs: list[Callable[[], None]] = []
        self._last_rotation_check = 0.0
        self._rotation_warned: set[str] = set()
        interval = coordinator.update_interval.total_seconds() \
            if coordinator.update_interval else DEFAULT_SCAN_INTERVAL
        self.stale_s = max(STALE_MIN_S, 4 * interval)

    # ------------------------------------------------------------ Lebenszyklus
    async def async_setup(self) -> None:
        entry = self.coordinator.config_entry
        for sid, sub in entry.subentries.items():
            if sub.subentry_type == SUBENTRY_PERSON:
                self.persons[sid] = Person(self, sub)
        if not self.persons:
            return
        for p in self.persons.values():
            for mac in p.macs:
                self.devices.setdefault(mac, DeviceState(mac=mac))
        self._update_devices(initial=True)
        now = time.time()
        for p in self.persons.values():
            p.evaluate(now, initial=True)
        self._unsubs.append(self.coordinator.async_add_listener(self._on_coordinator))
        if self.coordinator.logs is not None:
            self._unsubs.append(self.coordinator.logs.async_add_listener(self._on_log))
        sources = sorted({e for p in self.persons.values() for e in p.sources})
        if sources:
            self._unsubs.append(
                async_track_state_change_event(self.hass, sources, self._on_source))

    @callback
    def async_unload(self) -> None:
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()

    # ------------------------------------------------------------ Eingänge
    @callback
    def _on_coordinator(self) -> None:
        self._update_devices()
        self._evaluate_all()
        now = time.time()
        if now - self._last_rotation_check > ROTATION_CHECK_S:
            self._last_rotation_check = now
            self._check_rotation()

    @callback
    def _on_log(self, entry: dict, _ctx: Context | None) -> None:
        """Connect/Disconnect-Events: Verbindungen zwischen zwei Abrufen + Trennungs-AP."""
        event = (entry.get("event") or entry.get("key") or "").upper()
        mac = str(entry.get("client_mac") or "").lower()
        ds = self.devices.get(mac)
        if ds is None:
            return
        ts = dt_util.parse_datetime(entry.get("timestamp") or "")
        stamp = ts.timestamp() if ts else time.time()
        if ("CONNECTED" in event and "DISCONNECTED" not in event) or "ROAM" in event:
            ds.last_seen = max(ds.last_seen, stamp)
            ds.left_by_event = False
        elif "DISCONNECTED" in event:
            ds.last_seen = max(ds.last_seen, stamp)
            if (up := self._uplink_by_name(entry.get("device"))) is not None:
                ds.left_uplink = up
                ds.left_by_event = True

    @callback
    def _on_source(self, _event: Event) -> None:
        self._evaluate_all()

    def _evaluate_all(self) -> None:
        now = time.time()
        for p in self.persons.values():
            p.evaluate(now)

    # ------------------------------------------------------------ Geräte
    def _update_devices(self, initial: bool = False) -> None:
        data = self.coordinator.data
        if data is None:
            return
        now = time.time()
        users = data.users
        for mac, ds in self.devices.items():
            u = users.get(mac) or {}
            c = data.clients.get(mac)
            ds.known = bool(u or c)
            src = c or u
            ds.name = src.get("name") or src.get("hostname") or ds.name or mac
            ds.hostname = src.get("hostname") or ds.hostname
            if u.get("last_seen"):
                ds.last_seen = max(ds.last_seen, float(u["last_seen"]))
            was = ds.connected
            if c is not None:
                seen = float(c.get("last_seen") or now)
                ds.last_seen = max(ds.last_seen, seen)
                ds.connected = now - seen <= self.stale_s
                ds.wired = bool(c.get("is_wired"))
                ds.uplink = str(c.get("sw_mac") if ds.wired else c.get("ap_mac") or "").lower() \
                    or ds.uplink
                ds.ip = c.get("ip") or ds.ip
                ds.ssid = c.get("essid")
                ds.signal = c.get("signal") if c.get("signal") is not None else c.get("rssi")
            else:
                ds.connected = False
                ds.ip = ds.ip or u.get("last_ip")
                if initial and not ds.uplink:
                    up = u.get("last_uplink_mac") or u.get("last_connection_network_mac")
                    ds.uplink = str(up).lower() if up else None
            if ds.connected:
                ds.left_by_event = False
                ds.left_uplink = None
            elif was or (initial and not ds.left_uplink):
                if not ds.left_by_event:
                    ds.left_uplink = ds.uplink

    def device_present(self, mac: str) -> bool:
        """Anwesenheit eines Geräts mit der kürzesten Frist aller Personen, die es nutzen."""
        now = time.time()
        results = [p.device_present(mac, now)[0] for p in self.persons.values() if mac in p.macs]
        return any(results)

    # ------------------------------------------------------------ AP/Switch → Raum
    def uplink_name(self, mac: str | None) -> str:
        if not mac:
            return "?"
        dev = (self.coordinator.data.devices if self.coordinator.data else {}).get(mac) or {}
        return dev.get("name") or dev.get("model") or mac

    def uplink_room(self, mac: str | None) -> str:
        """Bereich des AP/Switch in HA (Geräte-Bereich), sonst dessen Name."""
        if not mac:
            return "Zuhause"
        entry_id = self.coordinator.config_entry.entry_id
        device = dr.async_get(self.hass).async_get_device(
            identifiers={(DOMAIN, f"{entry_id}_{mac}")})
        if device and device.area_id and (area := ar.async_get(self.hass).async_get_area(
                device.area_id)):
            return area.name
        return self.uplink_name(mac)

    def _uplink_by_name(self, name: Any) -> str | None:
        if not name or self.coordinator.data is None:
            return None
        for mac, dev in self.coordinator.data.devices.items():
            if dev.get("name") == name:
                return mac
        return None

    # ------------------------------------------------------------ Meldungen
    @callback
    def async_announce(self, person: Person, present: bool, trigger: str | None,
                       reason: str) -> None:
        data = {
            "person": person.name, "subentry_id": person.subentry_id,
            "state": "arrived" if present else "left",
            "trigger": trigger, "reason": reason, "room": person.room(),
        }
        self.hass.bus.async_fire(EVENT_PRESENCE, data)
        _LOGGER.info("Anwesenheit %s: %s (%s)", person.name, data["state"], reason)
        from .notifications import async_send, option_key  # noqa: PLC0415

        options = self.coordinator.config_entry.options
        if options.get(option_key("presence")):    # nur mit ausdrücklich gewählten Empfängern
            verb = "ist angekommen" if present else "ist gegangen"
            self.hass.async_create_task(async_send(
                self.hass, options, "presence", f"{person.name} {verb}",
                f"{person.name} {verb} – {reason}",
                {"tag": f"presence_{person.subentry_id}"}))

    def _check_rotation(self) -> None:
        """Private MAC lange ungesehen, aber neues Gerät mit gleichem Hostnamen → warnen."""
        data = self.coordinator.data
        if data is None:
            return
        now = time.time()
        for p in self.persons.values():
            for mac in p.macs:
                ds = self.devices.get(mac)
                if (ds is None or not is_private_mac(mac) or not ds.hostname
                        or mac in self._rotation_warned
                        or now - ds.last_seen < ROTATION_DAYS * 86_400):
                    continue
                newer = [m for m, u in data.users.items()
                         if m != mac and u.get("hostname") == ds.hostname
                         and float(u.get("last_seen") or 0) > ds.last_seen]
                if not newer:
                    continue
                self._rotation_warned.add(mac)
                msg = (f"Gerät **{ds.name}** von {p.name} nutzt offenbar wechselnde private "
                       f"MAC-Adressen: `{mac}` seit {ROTATION_DAYS}+ Tagen ungesehen, neu "
                       f"aktiv: `{', '.join(newer)}`.\n\nAm Gerät für dieses WLAN „private "
                       f"Adresse: fest“ (bzw. Geräte-MAC) einstellen und die Person neu "
                       f"konfigurieren.")
                _LOGGER.warning(msg.replace("**", "").replace("`", ""))
                from homeassistant.components import persistent_notification as pn  # noqa: PLC0415

                pn.async_create(self.hass, msg, title="Anwesenheit: wechselnde MAC",
                                notification_id=f"{DOMAIN}_mac_rotation_{mac}")


def device_options(coordinator: UniFiCoordinator) -> list[tuple[str, str]]:
    """Auswahlliste der Clients für den Personen-Dialog: (mac, Anzeigename)."""
    data = coordinator.data
    if data is None:
        return []
    now = time.time()
    out = []
    for mac, u in {**data.users, **data.clients}.items():
        c = data.clients.get(mac)
        name = (c or u).get("name") or (c or u).get("hostname") or (c or u).get("oui") or mac
        seen = float((c or u).get("last_seen") or 0)
        age = now - seen if seen else None
        status = "online" if c else (f"vor {int(age // 86_400)} d" if age and age > 86_400
                                     else "offline")
        flag = " · private MAC" if is_private_mac(mac) else ""
        out.append((mac, f"{name} ({mac}) – {status}{flag}", c is None, str(name).lower()))
    out.sort(key=lambda t: (t[2], t[3]))
    return [(m, label) for m, label, *_ in out]


def ap_options(coordinator: UniFiCoordinator) -> list[tuple[str, str]]:
    data = coordinator.data
    if data is None:
        return []
    return sorted(((mac, d.get("name") or d.get("model") or mac)
                   for mac, d in data.devices.items() if d.get("type") == "uap"),
                  key=lambda t: t[1].lower())
