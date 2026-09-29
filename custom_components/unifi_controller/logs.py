"""UniFi System-Log → HA-Events/Log-Datei + Fail2Ban über eine UniFi-Adressgruppe."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import datetime
import ipaddress
import logging
import re
from logging.handlers import RotatingFileHandler
import os
import time
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .api import UniFiApiError
from .const import (
    BAN_PLACEHOLDER,
    CONF_BAN_GROUP,
    CONF_F2B,
    CONF_F2B_BANTIME,
    CONF_F2B_CATEGORIES,
    CONF_F2B_FINDTIME,
    CONF_F2B_HA_LOGIN,
    CONF_F2B_INSTANT,
    CONF_F2B_MAXRETRY,
    CONF_F2B_WHITELIST,
    CONF_LOG_BACKFILL,
    CONF_LOG_FILE,
    CONF_LOGS,
    DEFAULT_BAN_GROUP,
    DEFAULT_F2B_BANTIME,
    DEFAULT_F2B_CATEGORIES,
    DEFAULT_F2B_FINDTIME,
    DEFAULT_F2B_INSTANT,
    DEFAULT_F2B_MAXRETRY,
    DOMAIN,
    EVENT_ALERT,
    EVENT_BAN,
    EVENT_LOG,
)

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

LOG_PATH = "v2/system-log/all"
PAGE_SIZE = 200
MAX_PAGES = 5

HA_LOGIN_NOTIFICATION = "http-login"
_IP_IN_PARENS = re.compile(r"\(([0-9A-Fa-f:.]+)\)")
_ANY_IP = re.compile(r"[0-9A-Fa-f:.]{7,}")

STAT_KEYS = ("events", "security", "threats", "fw_blocks", "ha_login", "bans")

EVENT_TYPES = ["security", "client", "device", "admin", "vpn", "system", "other"]


def event_type(category: str | None) -> str:
    c = (category or "").upper()
    if c.startswith("SECURITY") or c == "THREAT":
        return "security"
    if c.startswith("CLIENT"):
        return "client"
    if "DEVICE" in c:
        return "device"
    if c.startswith("ADMIN"):
        return "admin"
    if "VPN" in c:
        return "vpn"
    if c in {"SYSTEM", "UPDATES", "UPDATE", "INTERNET", "POWER"}:
        return "system"
    return "other"


def is_alert(entry: dict) -> bool:
    """Sicherheitsrelevant: IPS, Admin, HA-Login oder Security-Event von öffentlicher IP."""
    event = (entry.get("event") or "").upper()
    cat = (entry.get("category") or "").upper()
    if event.startswith("THREAT") or cat.startswith("ADMIN") or cat == "HA_LOGIN":
        return True
    ip = entry.get("src_ip")
    if cat == "SECURITY" and ip:
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False
    return False


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _param_ip(params: dict, *prefixes: str) -> str | None:
    for key, p in params.items():
        if not key.upper().startswith(prefixes) or not isinstance(p, dict):
            continue
        for cand in (p.get("ip"), p.get("name"), p.get("id")):
            if cand and _is_ip(cand):
                return str(cand)
    return None


def parse_entry(item: dict) -> dict[str, Any]:
    """System-Log-Eintrag in ein flaches, lesbares Dict umwandeln."""
    params = item.get("parameters") or {}
    msg = item.get("message_raw") or item.get("title_raw") or ""
    for key, p in params.items():
        val = p.get("name") or p.get("ip") or p.get("id") if isinstance(p, dict) else p
        msg = msg.replace("{" + key + "}", str(val or ""))
    client = params.get("SRC_CLIENT") or params.get("CLIENT") or {}
    device = params.get("DST_DEVICE") or params.get("DEVICE") or {}
    trigger = params.get("TRIGGER") or {}
    network = params.get("NETWORK") or {}
    ts = item.get("timestamp") or 0
    return {
        "id": item.get("id"),
        "timestamp": dt_util.utc_from_timestamp(ts / 1000).isoformat() if ts else None,
        "category": item.get("category"),
        "subcategory": item.get("subcategory"),
        "event": item.get("event"),
        "key": item.get("key"),
        "severity": item.get("severity"),
        "title": item.get("title_raw"),
        "message": msg,
        "src_ip": _param_ip(params, "SRC", "SOURCE", "IP", "ATTACKER", "REMOTE"),
        "dst_ip": _param_ip(params, "DST", "DEST", "TARGET"),
        "client": client.get("name") or client.get("hostname"),
        "client_mac": client.get("id"),
        "device": device.get("name"),
        "network": network.get("name"),
        "policy": trigger.get("name"),
    }


class LogManager:
    """Pollt das System-Log, verteilt Einträge und betreibt Fail2Ban."""

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        opts = coordinator.config_entry.options
        self.enabled: bool = opts.get(CONF_LOGS, True)
        self.log_file: str = (opts.get(CONF_LOG_FILE) or "").strip()
        self.f2b: bool = opts.get(CONF_F2B, False)
        self.maxretry: int = opts.get(CONF_F2B_MAXRETRY, DEFAULT_F2B_MAXRETRY)
        self.findtime: int = opts.get(CONF_F2B_FINDTIME, DEFAULT_F2B_FINDTIME)
        self.bantime: int = opts.get(CONF_F2B_BANTIME, DEFAULT_F2B_BANTIME)
        self.categories = {
            c.strip().upper()
            for c in opts.get(CONF_F2B_CATEGORIES, DEFAULT_F2B_CATEGORIES).split(",") if c.strip()
        }
        self.whitelist = [
            ipaddress.ip_network(w.strip(), strict=False)
            for w in (opts.get(CONF_F2B_WHITELIST) or "").split(",") if w.strip()
        ]
        self.group_name: str = opts.get(CONF_BAN_GROUP, DEFAULT_BAN_GROUP)
        self.instant = {
            e.strip().upper()
            for e in opts.get(CONF_F2B_INSTANT, DEFAULT_F2B_INSTANT).split(",") if e.strip()
        }
        self.ha_login: bool = opts.get(CONF_F2B_HA_LOGIN, True)
        self._unsub_login: Callable[[], None] | None = None
        backfill = int(opts.get(CONF_LOG_BACKFILL, 0))
        self._last_ts = int(time.time() * 1000) - backfill * 60_000
        self._seen: deque[str] = deque(maxlen=5000)
        self._hits: dict[str, deque[float]] = {}
        self._listeners: list[Callable[[dict], None]] = []
        self._writer: logging.Logger | None = None
        self._store: Store = Store(hass, 1, f"{DOMAIN}.{coordinator.config_entry.entry_id}.bans")
        self.bans: dict[str, dict[str, Any]] = {}
        self.last_error: str | None = None
        self.last_alert: dict[str, Any] | None = None
        self.last_ban: dict[str, Any] | None = None
        self.stats: dict[str, Any] = self._empty_stats()

    # -------------------------------------------------------------- Zähler
    @staticmethod
    def _empty_stats() -> dict[str, Any]:
        return {"date": dt_util.now().date().isoformat(), **{k: 0 for k in STAT_KEYS}}

    def _count(self, key: str) -> None:
        today = dt_util.now().date().isoformat()
        if self.stats.get("date") != today:
            self.stats = self._empty_stats()
        self.stats[key] = self.stats.get(key, 0) + 1

    def stat(self, key: str) -> int:
        if self.stats.get("date") != dt_util.now().date().isoformat():
            return 0
        return int(self.stats.get(key, 0))

    def _save(self) -> None:
        self._store.async_delay_save(
            lambda: {"bans": self.bans, "stats": self.stats, "last_alert": self.last_alert,
                     "last_ban": self.last_ban}, 10)

    @callback
    def _record(self, entry: dict) -> None:
        """Zähler + Alarmierung für einen Eintrag."""
        self._count("events")
        cat = (entry.get("category") or "").upper()
        event = (entry.get("event") or "").upper()
        if cat == "SECURITY":
            self._count("security")
        if event.startswith("THREAT"):
            self._count("threats")
        if event == "BLOCKED_BY_FIREWALL":
            self._count("fw_blocks")
        if cat == "HA_LOGIN":
            self._count("ha_login")
        if is_alert(entry):
            self.last_alert = {k: v for k, v in entry.items() if v is not None and k != "id"}
            self.hass.bus.async_fire(EVENT_ALERT, self.last_alert)
        self._save()

    # -------------------------------------------------------------- Setup
    async def async_setup(self) -> None:
        stored = await self._store.async_load() or {}
        self.bans = stored.get("bans", {})
        self.stats = stored.get("stats") or self._empty_stats()
        self.last_alert = stored.get("last_alert")
        self.last_ban = stored.get("last_ban")
        if self.enabled and self.log_file:
            self._writer = await self.hass.async_add_executor_job(self._open_file)
        if self.f2b and self.ha_login:
            self._watch_ha_logins()

    # -------------------------------------------------------------- HA-Logins
    def _watch_ha_logins(self) -> None:
        """Fehlgeschlagene HA-Anmeldungen (Benachrichtigung 'http-login') mitzählen."""
        try:
            from homeassistant.components import persistent_notification as pn  # noqa: PLC0415

            self._unsub_login = pn.async_register_callback(self.hass, self._on_notification)
        except (ImportError, AttributeError) as err:  # ältere/neuere Core-API
            _LOGGER.warning("HA-Login-Überwachung nicht verfügbar: %s", err)

    @callback
    def _on_notification(self, update_type: Any, notifications: dict[str, Any]) -> None:
        if str(getattr(update_type, "value", update_type)) not in ("added", "updated"):
            return
        note = notifications.get(HA_LOGIN_NOTIFICATION)
        if not note:
            return
        msg = str(note.get("message", ""))
        cands = _IP_IN_PARENS.findall(msg) or _ANY_IP.findall(msg)
        ip = next((c for c in reversed(cands) if _is_ip(c)), None)
        if not ip:
            return
        entry = {
            "category": "HA_LOGIN", "event": "HA_LOGIN_FAILED", "severity": "HIGH",
            "src_ip": ip, "message": msg.splitlines()[0] if msg else "",
            "timestamp": dt_util.utcnow().isoformat(),
        }
        self.hass.bus.async_fire(EVENT_LOG, entry)
        self._record(entry)
        self._check_f2b(entry, force_category=True)
        self.coordinator.async_update_listeners()

    def _open_file(self) -> logging.Logger:
        os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
        logger = logging.getLogger(f"{DOMAIN}.file.{self.coordinator.config_entry.entry_id}")
        logger.propagate = False
        logger.setLevel(logging.INFO)
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        handler = RotatingFileHandler(self.log_file, maxBytes=5_000_000, backupCount=3,
                                      encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        return logger

    def close(self) -> None:
        if self._unsub_login:
            self._unsub_login()
            self._unsub_login = None
        if self._writer:
            for h in list(self._writer.handlers):
                self._writer.removeHandler(h)
                h.close()

    @callback
    def async_add_listener(self, cb: Callable[[dict], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    # -------------------------------------------------------------- Polling
    async def async_poll(self) -> None:
        if self.enabled:
            try:
                await self._fetch_new()
                self.last_error = None
            except UniFiApiError as err:
                if self.last_error != str(err):
                    _LOGGER.warning("System-Log nicht abrufbar: %s", err)
                self.last_error = str(err)
        await self._expire_bans()

    async def fetch(self, ts_from: int, ts_to: int, page: int, size: int) -> dict:
        body = {"timestampFrom": ts_from, "timestampTo": ts_to,
                "pageNumber": page, "pageSize": size}
        data = await self.coordinator.client.request("POST", LOG_PATH, body)
        return data if isinstance(data, dict) else {"data": data or []}

    async def _fetch_new(self) -> None:
        now = int(time.time() * 1000)
        items: list[dict] = []
        for page in range(MAX_PAGES):
            res = await self.fetch(self._last_ts + 1, now, page, PAGE_SIZE)
            batch = res.get("data") or []
            items.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
        lines: list[str] = []
        for item in sorted(items, key=lambda i: i.get("timestamp") or 0):
            if not item.get("id") or item["id"] in self._seen:
                continue
            self._seen.append(item["id"])
            self._last_ts = max(self._last_ts, item.get("timestamp") or 0)
            entry = parse_entry(item)
            self.hass.bus.async_fire(EVENT_LOG, entry)
            for cb in list(self._listeners):
                cb(entry)
            lines.append(self._format(entry))
            self._record(entry)
            self._check_f2b(entry)
        if lines and self._writer:
            await self.hass.async_add_executor_job(self._write, lines)

    def _write(self, lines: list[str]) -> None:
        for line in lines:
            self._writer.info(line)

    @staticmethod
    def _format(e: dict) -> str:
        """Eine Zeile pro Ereignis – fail2ban-freundlich (src=<IP>)."""
        ts = e["timestamp"] or datetime.now().isoformat()
        parts = [ts, f"[{e['severity'] or '-'}]", e["category"] or "-", e["event"] or "-"]
        for k in ("src_ip", "dst_ip", "client", "client_mac", "network", "device", "policy"):
            if e.get(k):
                v = str(e[k]).replace('"', "'")
                parts.append(f'{k.replace("_ip", "")}="{v}"' if " " in v else
                             f"{k.replace('_ip', '')}={v}")
        parts.append(f'msg="{(e["message"] or "").replace(chr(34), chr(39))}"')
        return " ".join(parts)

    # -------------------------------------------------------------- Fail2Ban
    def _ignored(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return (not addr.is_global) or any(addr in n for n in self.whitelist)

    @callback
    def _check_f2b(self, entry: dict, force_category: bool = False) -> None:
        ip = entry.get("src_ip")
        if not self.f2b or not ip or ip in self.bans or self._ignored(ip):
            return
        event = (entry.get("event") or "").upper()
        if event in self.instant:
            self.bans[ip] = {"since": time.time(), "until": None, "reason": "pending"}
            self.hass.async_create_task(self._instant_ban(ip, event))
            return
        if (not force_category and self.categories
                and (entry.get("category") or "").upper() not in self.categories):
            return
        now = time.monotonic()
        hits = self._hits.setdefault(ip, deque())
        hits.append(now)
        while hits and now - hits[0] > self.findtime:
            hits.popleft()
        if len(hits) >= self.maxretry:
            self._hits.pop(ip, None)
            reason = f"{len(hits)}× {entry.get('event')} in {self.findtime}s"
            self.hass.async_create_task(self.async_ban(ip, self.bantime or None, reason))

    async def _instant_ban(self, ip: str, event: str) -> None:
        self.bans.pop(ip, None)  # Platzhalter gegen Doppel-Bans entfernen
        try:
            await self.async_ban(ip, self.bantime or None, f"{event} (sofort)")
        except UniFiApiError as err:
            _LOGGER.warning("Fail2Ban: Sperre von %s fehlgeschlagen: %s", ip, err)

    # Schreibzugriffe hier bewusst OHNE coordinator.async_command (kein Refresh aus
    # dem Poll heraus → keine Rekursion); Cache wird lokal nachgezogen.
    async def _load_groups(self) -> dict[str, dict]:
        groups = await self.coordinator.client.list_objects("rest/firewallgroup")
        indexed = {g["_id"]: g for g in groups if "_id" in g}
        if self.coordinator.data:
            self.coordinator.data.config["firewall_groups"] = indexed
        return indexed

    async def _group(self, create_with: str | None = None) -> dict | None:
        groups = await self._load_groups()
        for g in groups.values():
            if g.get("name") == self.group_name:
                return g
        if not create_with:
            return None
        await self.coordinator.client.create_object(
            "rest/firewallgroup",
            {"name": self.group_name, "group_type": "address-group",
             "group_members": [create_with]},
        )
        _LOGGER.warning(
            "Fail2Ban: Adressgruppe '%s' angelegt – eine Firewall-Policy mit dieser Gruppe als "
            "Quelle (Aktion BLOCK) muss sie noch verwenden", self.group_name)
        for g in (await self._load_groups()).values():
            if g.get("name") == self.group_name:
                return g
        return None

    async def _set_members(self, group: dict, members: list[str]) -> None:
        body = {**group, "group_members": members or [BAN_PLACEHOLDER]}
        await self.coordinator.client.update_object("rest/firewallgroup", group["_id"], body)
        group["group_members"] = body["group_members"]

    async def async_ban(self, ip: str, minutes: int | None, reason: str = "manuell") -> None:
        ipaddress.ip_address(ip)  # validiert
        group = await self._group(create_with=ip)
        if group is None:
            raise UniFiApiError(f"Adressgruppe '{self.group_name}' konnte nicht angelegt werden")
        current = [m for m in group.get("group_members", []) if m != BAN_PLACEHOLDER]
        if ip not in current:
            await self._set_members(group, sorted({*current, ip}))
        now = time.time()
        self.bans[ip] = {"since": now, "until": now + minutes * 60 if minutes else None,
                         "reason": reason}
        self._count("bans")
        self.last_ban = {"ip": ip, "reason": reason, "minutes": minutes,
                         "time": dt_util.utcnow().isoformat()}
        self._save()
        _LOGGER.warning("Fail2Ban: %s gesperrt (%s)", ip, reason)
        self.hass.bus.async_fire(EVENT_BAN, {"action": "ban", "ip": ip, "reason": reason,
                                             "minutes": minutes})
        self.coordinator.async_update_listeners()

    async def async_unban(self, ip: str) -> None:
        had = self.bans.pop(ip, None) is not None
        if had:
            self._save()
        try:
            group = await self._group()
            if group is not None and ip in group.get("group_members", []):
                await self._set_members(group, [m for m in group["group_members"] if m != ip])
        except UniFiApiError:
            if had:  # Zustand wiederherstellen, beim nächsten Poll erneut versuchen
                self.bans[ip] = {"since": time.time(), "until": time.time(), "reason": "retry"}
            raise
        self.hass.bus.async_fire(EVENT_BAN, {"action": "unban", "ip": ip})
        self.coordinator.async_update_listeners()

    async def _expire_bans(self) -> None:
        now = time.time()
        for ip in [ip for ip, b in self.bans.items() if b.get("until") and b["until"] < now]:
            try:
                await self.async_unban(ip)
            except UniFiApiError as err:
                _LOGGER.warning("Fail2Ban: Entsperren von %s fehlgeschlagen: %s", ip, err)

    def ban_list(self) -> dict[str, dict[str, Any]]:
        return {
            ip: {
                "since": dt_util.utc_from_timestamp(b["since"]).isoformat(),
                "until": dt_util.utc_from_timestamp(b["until"]).isoformat() if b.get("until") else None,
                "reason": b.get("reason"),
            }
            for ip, b in self.bans.items()
        }
