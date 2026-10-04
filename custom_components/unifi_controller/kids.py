"""Kinderprofile: Internet-Freigabe mit Zeitplan, Bonuszeit, Geräte-Zuordnung.

Ein Kind ist ein Config-Subentry (Typ „kid“) mit einem eigenen Netz. Pro Kind gibt es zwei
Firewall-Policies „Sperre <n> Internet“ und „Sperre <n> IoT“ (Quelle = Subnetz des Kindes).
Online = beide Policies deaktiviert, offline = beide aktiv. Der Zustand wird immer aus der
Internet-Policy abgelesen – die Policy ist die Wahrheit, HA speichert nur Zeiten und Bonus.

Zeitplan (wie die frühere HA-Automation):
  * morgens zur Freigabezeit → online (Bonus verfällt)
  * abends Sperre: So–Do zur Schultag-Zeit, Fr/Sa zur Wochenend-Zeit → offline
    (läuft eine Bonuszeit, wird bis zu deren Ende verschoben)
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, time, timedelta
import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.components import persistent_notification as pn
from homeassistant.config_entries import ConfigSubentry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_point_in_time, async_track_time_change
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .api import UniFiApiError
from .const import DOMAIN
from .region import zone_id

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

SUBENTRY_KID = "kid"
CONF_NAME = "name"
CONF_NETWORK = "network_id"
CONF_UNLOCK = "unlock"
CONF_LOCK_SCHOOL = "lock_school"
CONF_LOCK_WEEKEND = "lock_weekend"
CONF_SCHEDULE = "schedule"

DEFAULT_UNLOCK = "06:30:00"
DEFAULT_LOCK_SCHOOL = "20:00:00"
DEFAULT_LOCK_WEEKEND = "21:00:00"
TIME_KEYS = (CONF_UNLOCK, CONF_LOCK_SCHOOL, CONF_LOCK_WEEKEND)

SCHOOL_EVENINGS = {6, 0, 1, 2, 3}   # So, Mo–Do (date.weekday(): Mo=0 … So=6)
WEEKEND_EVENINGS = {4, 5}           # Fr, Sa
VERIFY_DELAY_S = 30
FW = "firewall_policies"


def policy_names(name: str) -> tuple[str, str]:
    return f"Sperre {name} Internet", f"Sperre {name} IoT"


def parse_time(value: Any, default: str) -> time:
    if isinstance(value, time):
        return value
    try:
        return time.fromisoformat(str(value or default))
    except ValueError:
        return time.fromisoformat(default)


def subnet_of(net: dict) -> str | None:
    try:
        return str(ipaddress.ip_interface(net["ip_subnet"]).network)
    except (KeyError, ValueError):
        return None


def kid_zone(data) -> str | None:
    return zone_id(data, "kinder") or zone_id(data, "kids")


# --------------------------------------------------------------------- Netz anlegen
def next_free_network(data) -> tuple[int, str]:
    """Nächste freie VLAN-ID und 192.168.x.0/24 – setzt das Muster der Kindernetze fort
    (z. B. 41, 42, 43 → 44), sonst erstes freies Netz ab 192.168.40.0/24."""
    nets = list(data.config.get("networks", {}).values())
    zone = kid_zone(data)
    vlans = {n.get("vlan") for n in nets if n.get("vlan")}
    used, kid_octets = [], []
    for n in nets:
        try:
            net = ipaddress.ip_interface(n["ip_subnet"]).network
        except (KeyError, ValueError):
            continue
        used.append(net)
        if zone and n.get("firewall_zone_id") == zone and str(net).startswith("192.168."):
            kid_octets.append(int(str(net).split(".")[2]))
    kid_vlans = [n.get("vlan") for n in nets
                 if zone and n.get("firewall_zone_id") == zone and n.get("vlan")]

    def free(o: int) -> bool:
        cand = ipaddress.ip_network(f"192.168.{o}.0/24")
        return not any(cand.overlaps(u) for u in used)

    start = max(kid_octets) + 1 if kid_octets else 40
    octet = next((o for o in range(start, 255) if free(o)), None) or \
        next(o for o in range(40, 255) if free(o))
    vstart = max(kid_vlans) + 1 if kid_vlans else 3
    vlan = next((v for v in range(vstart, 4000) if v not in vlans), None) or \
        next(v for v in range(3, 4000) if v not in vlans)
    return vlan, f"192.168.{octet}"


async def async_create_network(coordinator: UniFiCoordinator, name: str) -> str:
    data = coordinator.data
    zone = kid_zone(data)
    if not zone:
        raise UniFiApiError("Firewall-Zone „Kinder“ nicht gefunden")
    vlan, base = next_free_network(data)
    body = {
        "name": name, "purpose": "corporate", "networkgroup": "LAN",
        "vlan_enabled": True, "vlan": vlan, "ip_subnet": f"{base}.1/24",
        "dhcpd_enabled": True, "dhcpd_start": f"{base}.20", "dhcpd_stop": f"{base}.250",
        "firewall_zone_id": zone, "internet_access_enabled": True, "mdns_enabled": True,
        "network_isolation_enabled": True, "setting_preference": "manual",
        "ipv6_setting_preference": "manual", "enabled": True,
    }
    res = await coordinator.async_command(
        coordinator.client.create_object("rest/networkconf", body))
    created = (res[0] if isinstance(res, list) and res else res) or {}
    if not created.get("_id"):
        raise UniFiApiError("Netz konnte nicht angelegt werden")
    _LOGGER.info("Kindernetz %s angelegt: VLAN %s, %s.0/24", name, vlan, base)
    return created["_id"]


# --------------------------------------------------------------------- Kind
class Kid:
    """Laufzeit-Steuerung eines Kinderprofils."""

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator,
                 subentry: ConfigSubentry, state: dict[str, Any], save: Callable[[], None]) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.subentry_id = subentry.subentry_id
        self.name: str = subentry.data[CONF_NAME]
        self.network_id: str = subentry.data[CONF_NETWORK]
        self._state = state          # gehört dem KidManager, wird gespeichert
        self._save = save
        self._unsubs: list[Callable[[], None]] = []
        self._bonus_unsub: Callable[[], None] | None = None
        self.listeners: list[Callable[[], None]] = []
        for key in TIME_KEYS:
            self._state.setdefault(key, subentry.data.get(key) or {
                CONF_UNLOCK: DEFAULT_UNLOCK, CONF_LOCK_SCHOOL: DEFAULT_LOCK_SCHOOL,
                CONF_LOCK_WEEKEND: DEFAULT_LOCK_WEEKEND}[key])
        self._state.setdefault(CONF_SCHEDULE, subentry.data.get(CONF_SCHEDULE, True))

    # ------------------------------------------------------------ Zustand
    @property
    def network(self) -> dict | None:
        return self.coordinator.data.config.get("networks", {}).get(self.network_id)

    def policy(self, which: int) -> dict | None:
        want = policy_names(self.name)[which]
        for p in self.coordinator.data.config.get(FW, {}).values():
            if p.get("name") == want and not p.get("predefined"):
                return p
        return None

    @property
    def online(self) -> bool | None:
        p = self.policy(0)
        return None if p is None else not p.get("enabled")

    @property
    def schedule(self) -> bool:
        return bool(self._state.get(CONF_SCHEDULE))

    def get_time(self, key: str) -> time:
        return parse_time(self._state.get(key), DEFAULT_UNLOCK)

    @property
    def bonus_until(self) -> datetime | None:
        ts = self._state.get("bonus_until")
        if not ts:
            return None
        value = dt_util.parse_datetime(ts)
        return value if value and value > dt_util.utcnow() else None

    def devices(self) -> list[dict[str, Any]]:
        """Dem Kindernetz zugeordnete Geräte (Override) + aktuell verbundene."""
        out: dict[str, dict[str, Any]] = {}
        for mac, u in self.coordinator.data.users.items():
            if u.get("virtual_network_override_enabled") and \
                    u.get("virtual_network_override_id") == self.network_id:
                out[mac] = {"mac": mac, "name": u.get("name") or u.get("hostname") or mac,
                            "zugeordnet": True, "online": False, "ip": u.get("last_ip")}
        for mac, c in self.coordinator.data.clients.items():
            if c.get("network_id") == self.network_id:
                entry = out.setdefault(mac, {"mac": mac, "zugeordnet": False})
                entry.update(name=c.get("name") or c.get("hostname") or mac,
                             online=True, ip=c.get("ip"))
        return sorted(out.values(), key=lambda d: (not d["online"], d["name"].lower()))

    def _notify(self) -> None:
        for cb in list(self.listeners):
            cb()

    # ------------------------------------------------------------ Policies
    async def async_ensure_policies(self) -> None:
        """Fehlende Sperr-Policies anlegen (deaktiviert = online)."""
        data = self.coordinator.data
        net = self.network
        if not net:
            _LOGGER.warning("Kind %s: Netz %s fehlt", self.name, self.network_id)
            return
        src_zone = net.get("firewall_zone_id") or kid_zone(data)
        subnet = subnet_of(net)
        targets = [(0, zone_id(data, "external")), (1, zone_id(data, "iot"))]
        for which, dst in targets:
            if self.policy(which) is not None or not dst or not subnet or not src_zone:
                continue
            body = {
                "action": "BLOCK", "connection_state_type": "ALL", "connection_states": [],
                "create_allow_respond": False, "enabled": False, "icmp_typename": "ANY",
                "icmp_v6_typename": "ANY", "ip_version": "IPV4", "logging": False,
                "match_ip_sec": False, "match_opposite_protocol": False,
                "name": policy_names(self.name)[which], "protocol": "all",
                "description": f"Kinderprofil {self.name} (UniFi Controller Manager)",
                "schedule": {"mode": "ALWAYS"},
                "source": {"ips": [subnet], "match_mac": False, "match_opposite_ips": False,
                           "match_opposite_ports": False, "matching_target": "IP",
                           "matching_target_type": "SPECIFIC", "port_matching_type": "ANY",
                           "zone_id": src_zone},
                "destination": {"match_opposite_ports": False, "matching_target": "ANY",
                                "port_matching_type": "ANY", "zone_id": dst},
            }
            await self.coordinator.async_command(
                self.coordinator.client.create_object("v2/firewall-policies", body))
            _LOGGER.info("Kind %s: Policy „%s“ angelegt", self.name, body["name"])

    async def async_set_online(self, online: bool, reason: str = "") -> None:
        for which in (0, 1):
            p = self.policy(which)
            if p is not None and bool(p.get("enabled")) == online:
                await self.coordinator.async_update_object(FW, p, {"enabled": not online})
        _LOGGER.info("Kind %s: %s (%s)", self.name, "online" if online else "offline", reason)
        self.hass.loop.call_later(VERIFY_DELAY_S, lambda: self.hass.async_create_task(
            self._async_verify(online)))
        self._notify()

    async def _async_verify(self, online: bool) -> None:
        self.coordinator._force_config = True  # noqa: SLF001
        await self.coordinator.async_refresh()
        wrong = [policy_names(self.name)[w] for w in (0, 1)
                 if (p := self.policy(w)) is not None and bool(p.get("enabled")) == online]
        if wrong:
            msg = f"{self.name} sollte {'online' if online else 'offline'} sein, aber: " \
                  + ", ".join(wrong) + " nicht übernommen."
            _LOGGER.warning(msg)
            pn.async_create(self.hass, msg, title="Kinder-Internet: Sperre nicht übernommen",
                            notification_id=f"{DOMAIN}_kid_{self.subentry_id}")

    # ------------------------------------------------------------ Zeitplan
    @callback
    def async_start(self) -> None:
        self.async_stop()
        for key, handler in ((CONF_UNLOCK, self._on_unlock),
                             (CONF_LOCK_SCHOOL, self._on_lock_school),
                             (CONF_LOCK_WEEKEND, self._on_lock_weekend)):
            t = self.get_time(key)
            self._unsubs.append(async_track_time_change(
                self.hass, handler, hour=t.hour, minute=t.minute, second=t.second))
        if (until := self.bonus_until) is not None and self.online:
            self._schedule_bonus_end(until)

    @callback
    def async_stop(self) -> None:
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        if self._bonus_unsub:
            self._bonus_unsub()
            self._bonus_unsub = None

    async def _on_unlock(self, _now: datetime) -> None:
        if not self.schedule:
            return
        self._state["bonus_until"] = None
        self._save()
        await self.async_set_online(True, "Freigabe morgens")

    async def _on_lock_school(self, now: datetime) -> None:
        if dt_util.as_local(now).weekday() in SCHOOL_EVENINGS:
            await self._lock_by_schedule("Sperre Schultag")

    async def _on_lock_weekend(self, now: datetime) -> None:
        if dt_util.as_local(now).weekday() in WEEKEND_EVENINGS:
            await self._lock_by_schedule("Sperre Wochenende")

    async def _lock_by_schedule(self, reason: str) -> None:
        if not self.schedule:
            return
        if (until := self.bonus_until) is not None:
            _LOGGER.info("Kind %s: %s wegen Bonus bis %s verschoben", self.name, reason, until)
            self._schedule_bonus_end(until)
            return
        await self.async_set_online(False, reason)

    @callback
    def _schedule_bonus_end(self, until: datetime) -> None:
        if self._bonus_unsub:
            self._bonus_unsub()

        async def _end(_now: datetime) -> None:
            self._bonus_unsub = None
            self._state["bonus_until"] = None
            self._save()
            await self.async_set_online(False, "Bonuszeit abgelaufen")

        self._bonus_unsub = async_track_point_in_time(self.hass, _end, until)

    # ------------------------------------------------------------ Bedienung
    async def async_set_schedule(self, enabled: bool) -> None:
        self._state[CONF_SCHEDULE] = enabled
        self._save()
        self._notify()

    async def async_set_time(self, key: str, value: time) -> None:
        self._state[key] = value.isoformat()
        self._save()
        self.async_start()
        self._notify()

    async def async_bonus(self, minutes: int) -> datetime:
        """Bonuszeit: gesperrt → sofort frei bis jetzt+x; frei → abendliche Sperre verschiebt sich."""
        now = dt_util.utcnow()
        start = max(now, self.bonus_until or now)
        until = start + timedelta(minutes=minutes)
        self._state["bonus_until"] = until.isoformat()
        self._save()
        if self.online is False:
            await self.async_set_online(True, f"Bonus {minutes} min")
            self._schedule_bonus_end(until)
        elif self._bonus_unsub:          # läuft schon ein Bonus nach der Sperrzeit → verlängern
            self._schedule_bonus_end(until)
        self._notify()
        return until

    async def async_cancel_bonus(self) -> None:
        self._state["bonus_until"] = None
        self._save()
        if self._bonus_unsub:
            self._bonus_unsub()
            self._bonus_unsub = None
        self._notify()


class KidManager:
    """Alle Kinderprofile einer Config-Entry; Zustand persistent in einem Store."""

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        entry = coordinator.config_entry
        self._store: Store = Store(hass, 1, f"{DOMAIN}.{entry.entry_id}.kids")
        self._data: dict[str, Any] = {}
        self.kids: dict[str, Kid] = {}

    def _save(self) -> None:
        self._store.async_delay_save(lambda: self._data, 2)

    async def async_setup(self) -> None:
        self._data = await self._store.async_load() or {"kids": {}}
        entry = self.coordinator.config_entry
        current = {sid: s for sid, s in entry.subentries.items() if s.subentry_type == SUBENTRY_KID}
        # entfernte Kinder aufräumen: Sperr-Policies löschen, Netz + Geräte bleiben
        for sid in [s for s in self._data["kids"] if s not in current]:
            await self._async_cleanup(sid, self._data["kids"].pop(sid))
        for sid, sub in current.items():
            state = self._data["kids"].setdefault(sid, {})
            old_name = state.get("name")
            state["name"] = sub.data[CONF_NAME]
            state["network_id"] = sub.data[CONF_NETWORK]
            if sub.data.get("rev") != state.get("rev"):   # neu angelegt / neu konfiguriert
                for key in (*TIME_KEYS, CONF_SCHEDULE):
                    if key in sub.data:
                        state[key] = sub.data[key]
                state["rev"] = sub.data.get("rev")
            kid = Kid(self.hass, self.coordinator, sub, state, self._save)
            if old_name and old_name != kid.name:
                await self._async_rename_policies(old_name, kid.name)
            try:
                await kid.async_ensure_policies()
            except UniFiApiError as err:
                _LOGGER.warning("Kind %s: Policies nicht anlegbar: %s", kid.name, err)
            kid.async_start()
            self.kids[sid] = kid
        self._save()

    @callback
    def async_unload(self) -> None:
        for kid in self.kids.values():
            kid.async_stop()

    async def _async_rename_policies(self, old: str, new: str) -> None:
        for old_name, new_name in zip(policy_names(old), policy_names(new), strict=True):
            for p in list(self.coordinator.data.config.get(FW, {}).values()):
                if p.get("name") == old_name:
                    await self.coordinator.async_update_object(FW, p, {"name": new_name})

    async def _async_cleanup(self, sid: str, state: dict[str, Any]) -> None:
        name = state.get("name")
        if not name:
            return
        for pname in policy_names(name):
            for p in list(self.coordinator.data.config.get(FW, {}).values()):
                if p.get("name") == pname and not p.get("predefined"):
                    try:
                        await self.coordinator.async_command(
                            self.coordinator.client.delete_object("v2/firewall-policies", p["_id"]))
                        _LOGGER.info("Kind %s entfernt: Policy „%s“ gelöscht", name, pname)
                    except UniFiApiError as err:
                        _LOGGER.warning("Policy „%s“ nicht löschbar: %s", pname, err)

    def find(self, ident: str) -> Kid | None:
        for sid, kid in self.kids.items():
            if ident in (sid, kid.network_id) or ident.lower() == kid.name.lower():
                return kid
        return None

    async def async_assign_device(self, mac: str, network_id: str | None) -> None:
        """Gerät einem Netz zuordnen (Override) – None hebt die Zuordnung auf – und neu verbinden."""
        mac = mac.lower()
        user = self.coordinator.data.users.get(mac)
        if user is None:
            raise UniFiApiError(f"Gerät {mac} ist dem Controller nicht bekannt")
        changes = ({"virtual_network_override_enabled": True,
                    "virtual_network_override_id": network_id}
                   if network_id else {"virtual_network_override_enabled": False})
        await self.coordinator.async_update_object("users", user, changes)
        if mac in self.coordinator.data.clients:
            try:
                await self.coordinator.client.stamgr("kick-sta", mac)
            except UniFiApiError:
                pass   # kabelgebunden o. ä. – Zuordnung greift beim nächsten Verbinden
