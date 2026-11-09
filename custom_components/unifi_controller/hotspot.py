"""Hotspot-Webhooks der Konsole (ab Network 11.1.47) und Gast-Freigabe aus Home Assistant.

Die Konsole schickt an die auf der Hotspot-Seite eingetragene URL:
- ``guest.signed_in``                – Gast am Portal angemeldet,
- ``personal_wifi_password.created`` – Gast hat ein eigenes WLAN-Passwort (das Passwort wird
                                       hier NIE gespeichert, geloggt oder weitergegeben),
- ``test``                           – Test-Knopf,
- ``guest.verify``                   – External Authorization: darf der Gast online?

Bei ``guest.verify`` entscheidet der Modus: immer zulassen, immer ablehnen oder nachfragen
(Push mit Zulassen/Ablehnen, Knöpfe im Dashboard, Dienst ``hotspot_decide``). Ohne Antwort
innerhalb des Timeouts gilt die eingestellte Vorgabe. Signaturen (HMAC-SHA256 über
``"<t>.<body>"``) werden geprüft, sobald ein Secret eingetragen ist; für ``guest.verify`` ist
das Secret Pflicht – ohne gültige Signatur wird nie freigegeben.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from homeassistant.components import persistent_notification as pn
from homeassistant.components import webhook
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.util import dt as dt_util

from .const import (
    CONF_HS_DATA_MB,
    CONF_HS_DOWN,
    CONF_HS_MINUTES,
    CONF_HS_MODE,
    CONF_HS_ON_TIMEOUT,
    CONF_HS_SECRET,
    CONF_HS_TIMEOUT,
    CONF_HS_UP,
    CONF_HS_WEBHOOK_ID,
    DEFAULT_HS_MODE,
    DEFAULT_HS_ON_TIMEOUT,
    DEFAULT_HS_TIMEOUT,
    DOMAIN,
    EVENT_HOTSPOT,
)

if TYPE_CHECKING:
    from .coordinator import UniFiConfigEntry, UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

MODES = ["ask", "allow", "deny", "off"]
MAX_SKEW_S = 300
MAX_BODY = 64 * 1024
ACTION_PREFIX = "UNIFI_HOTSPOT_"
EVENT_TYPES = ["guest_signed_in", "personal_password", "verify_request", "approved", "denied",
               "test"]


@dataclass
class Request:
    rid: str
    guest: dict[str, Any]
    ssid: str | None
    ap: str | None
    created: float = field(default_factory=time.time)
    future: asyncio.Future = field(default_factory=lambda: asyncio.get_running_loop().create_future())

    def label(self) -> str:
        g = self.guest
        name = " ".join(x for x in (g.get("first_name"), g.get("last_name")) if x)
        who = name or g.get("email") or g.get("mac") or "?"
        room = f", Zimmer {g['room_number']}" if g.get("room_number") else ""
        return f"{who}{room}"

    def as_dict(self) -> dict[str, Any]:
        g = self.guest
        return {"id": self.rid, "mac": g.get("mac"), "email": g.get("email"),
                "name": " ".join(x for x in (g.get("first_name"), g.get("last_name")) if x) or None,
                "zimmer": g.get("room_number"), "ssid": self.ssid, "access_point": self.ap,
                "seit": dt_util.utc_from_timestamp(self.created).isoformat()}


def verify_signature(secret: str, raw: bytes, header: str | None, now: float | None = None) -> bool:
    """``X-UniFi-Signature: t=<unix>,v1=<hex>`` prüfen (konstante Laufzeit, max. 5 min alt)."""
    if not secret or not header:
        return False
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    try:
        ts = int(parts.get("t", ""))
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > MAX_SKEW_S:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def approval(minutes: int = 0, down: int = 0, up: int = 0, data_mb: int = 0,
             now: float | None = None) -> dict[str, Any]:
    """Antwort für eine Freigabe; Grenzen wie in der API (sonst wertet die Konsole als Ablehnung)."""
    out: dict[str, Any] = {"approved": True}
    if minutes:
        out["expires_at"] = int((now or time.time()) + min(int(minutes), 30 * 24 * 60) * 60)
    if down:
        out["rate_limit_down_kbps"] = max(2, min(int(down), 100000))
    if up:
        out["rate_limit_up_kbps"] = max(2, min(int(up), 100000))
    if data_mb:
        out["data_limit_mb"] = max(1, min(int(data_mb), 1048576))
    return out


class Hotspot:
    """Webhook-Empfänger + offene Freigabe-Anfragen."""

    def __init__(self, hass: HomeAssistant, entry: UniFiConfigEntry,
                 coordinator: UniFiCoordinator) -> None:
        self.hass = hass
        self.entry = entry
        self.c = coordinator
        self.pending: dict[str, Request] = {}
        self.last: dict[str, Any] | None = None
        self._listeners: list[Callable[[str, dict[str, Any]], None]] = []
        self._unsub: Callable[[], None] | None = None

    # ------------------------------------------------------------ Einrichtung
    @property
    def webhook_id(self) -> str:
        return self.entry.data[CONF_HS_WEBHOOK_ID]

    @property
    def url(self) -> str:
        try:
            return webhook.async_generate_url(self.hass, self.webhook_id, prefer_external=True)
        except Exception:  # noqa: BLE001 – keine URL konfiguriert
            return webhook.async_generate_path(self.webhook_id)

    def opt(self, key: str, default: Any = None) -> Any:
        return self.entry.options.get(key, default)

    async def async_setup(self) -> None:
        if not self.entry.data.get(CONF_HS_WEBHOOK_ID):
            self.hass.config_entries.async_update_entry(
                self.entry, data={**self.entry.data,
                                  CONF_HS_WEBHOOK_ID: f"unifi_hotspot_{secrets.token_hex(16)}"})
        webhook.async_register(self.hass, DOMAIN, f"UniFi Hotspot ({self.entry.title})",
                               self.webhook_id, self._handle, local_only=False,
                               allowed_methods=["POST"])
        self._unsub = self.hass.bus.async_listen("mobile_app_notification_action", self._on_action)

    @callback
    def async_unload(self) -> None:
        webhook.async_unregister(self.hass, self.webhook_id)
        if self._unsub:
            self._unsub()
        for req in self.pending.values():
            if not req.future.done():
                req.future.set_result(None)

    @callback
    def async_add_listener(self, cb: Callable[[str, dict[str, Any]], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    @callback
    def _emit(self, kind: str, data: dict[str, Any]) -> None:
        self.last = {"art": kind, **data, "zeit": dt_util.utcnow().isoformat()}
        self.hass.bus.async_fire(EVENT_HOTSPOT, {"entry_id": self.entry.entry_id, "art": kind, **data})
        for cb in list(self._listeners):
            cb(kind, data)

    # ------------------------------------------------------------ Empfang
    async def _handle(self, hass: HomeAssistant, webhook_id: str,
                      request: web.Request) -> web.Response:
        raw = await request.content.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            return web.Response(status=413)
        try:
            body = json.loads(raw)
            event = str(body["event"])
        except (ValueError, KeyError, TypeError):
            return web.Response(status=400)
        secret = self.opt(CONF_HS_SECRET) or ""
        signed = verify_signature(secret, raw, request.headers.get("X-UniFi-Signature"))
        if secret and not signed:
            _LOGGER.warning("Hotspot-Webhook %s mit ungültiger/fehlender Signatur abgelehnt "
                            "(Secret auf der Hotspot-Seite und in den Optionen gleich?)", event)
            return web.Response(status=401)
        if event == "guest.verify":
            if not signed:
                _LOGGER.warning("External Authorization ohne Secret – Gast abgelehnt. Secret "
                                "(whsec_…) in den Optionen unter „Hotspot“ eintragen.")
                return web.json_response({"approved": False})
            return web.json_response(await self._verify(body))
        guest = body.get("guest") or {}
        if event == "guest.signed_in":
            self._emit("guest_signed_in", {
                "mac": guest.get("mac"), "email": guest.get("email"),
                "name": " ".join(x for x in (guest.get("first_name"), guest.get("last_name")) if x) or None,
                "ssid": body.get("ssid"), "access_point": self._ap_name(body.get("access_point_mac")),
                "freigabe": body.get("authorized_by"),
                "bis": _ts(body.get("expires_at"))})
        elif event == "personal_wifi_password.created":
            self._emit("personal_password", {   # Passwort bewusst NICHT übernehmen
                "mac": guest.get("mac"), "email": guest.get("email"), "ssid": body.get("ssid"),
                "bis": _ts(body.get("expires_at"))})
        elif event == "test":
            self._emit("test", {"signiert": signed})
            pn.async_create(self.hass, f"Test-Webhook vom Hotspot empfangen "
                            f"({'Signatur gültig' if signed else 'ohne Signatur'}).",
                            title="UniFi Hotspot", notification_id=f"{DOMAIN}_hotspot_test")
        else:
            _LOGGER.debug("Unbekanntes Hotspot-Ereignis %s", event)
        return web.Response(status=200)

    def _ap_name(self, mac: str | None) -> str | None:
        if not mac or not self.c.data:
            return mac
        dev = self.c.data.devices.get(mac.lower())
        return (dev or {}).get("name") or mac

    def _limits(self) -> dict[str, int]:
        return {"minutes": int(self.opt(CONF_HS_MINUTES, 0) or 0),
                "down": int(self.opt(CONF_HS_DOWN, 0) or 0),
                "up": int(self.opt(CONF_HS_UP, 0) or 0),
                "data_mb": int(self.opt(CONF_HS_DATA_MB, 0) or 0)}

    async def _verify(self, body: dict[str, Any]) -> dict[str, Any]:
        mode = self.opt(CONF_HS_MODE, DEFAULT_HS_MODE)
        req = Request(secrets.token_hex(4), body.get("guest") or {}, body.get("ssid"),
                      self._ap_name(body.get("access_point_mac")))
        info = req.as_dict()
        if mode in ("deny", "off"):
            self._emit("denied", {**info, "grund": "Modus ablehnen"})
            return {"approved": False}
        if mode == "allow":
            self._emit("approved", {**info, "grund": "Modus immer zulassen"})
            return approval(**self._limits())
        # nachfragen
        self.pending[req.rid] = req
        self._emit("verify_request", info)
        await self._notify(req)
        timeout = int(self.opt(CONF_HS_TIMEOUT, DEFAULT_HS_TIMEOUT))
        try:
            decision = await asyncio.wait_for(asyncio.shield(req.future), timeout)
        except TimeoutError:
            decision = None
        self.pending.pop(req.rid, None)
        self._clear(req)
        if decision is None:
            allow = self.opt(CONF_HS_ON_TIMEOUT, DEFAULT_HS_ON_TIMEOUT) == "allow"
            self._emit("approved" if allow else "denied", {**info, "grund": "keine Antwort"})
            return approval(**self._limits()) if allow else {"approved": False}
        if decision.get("approved"):
            self._emit("approved", {**info, "grund": decision.get("von", "manuell")})
            return approval(**{**self._limits(), **{k: v for k, v in decision.items()
                                                    if k in ("minutes", "down", "up", "data_mb")
                                                    and v is not None}})
        self._emit("denied", {**info, "grund": decision.get("von", "manuell")})
        return {"approved": False}

    async def _notify(self, req: Request) -> None:
        from .notifications import async_send  # noqa: PLC0415

        timeout = int(self.opt(CONF_HS_TIMEOUT, DEFAULT_HS_TIMEOUT))
        msg = (f"{req.label()} möchte ins WLAN {req.ssid or ''}"
               f"{f' (AP {req.ap})' if req.ap else ''}. Antwort innerhalb {timeout} s – "
               "„Zulassen“/„Ablehnen“ in der Meldung oder im Dashboard.")
        await async_send(self.hass, self.entry.options, "hotspot", "WLAN-Gast wartet", msg, {
            "tag": f"hotspot_{req.rid}", "ttl": 0, "priority": "high",
            "actions": [{"action": f"{ACTION_PREFIX}ALLOW_{req.rid}", "title": "Zulassen"},
                        {"action": f"{ACTION_PREFIX}DENY_{req.rid}", "title": "Ablehnen"}]})

    def _clear(self, req: Request) -> None:
        pn.async_dismiss(self.hass, f"{DOMAIN}_hotspot_{req.rid}")

    @callback
    def _on_action(self, event: Event) -> None:
        action = str(event.data.get("action") or "")
        if not action.startswith(ACTION_PREFIX):
            return
        verb, _, rid = action.removeprefix(ACTION_PREFIX).partition("_")
        if rid in self.pending:
            self.decide(rid, verb == "ALLOW", von="Push")

    # ------------------------------------------------------------ Entscheidung
    @callback
    def decide(self, rid: str | None, approve: bool, *, von: str = "manuell",
               minutes: int | None = None, down: int | None = None, up: int | None = None,
               data_mb: int | None = None) -> str:
        if not self.pending:
            raise ServiceValidationError("Kein WLAN-Gast wartet gerade auf Freigabe")
        if rid is None:
            rid = min(self.pending.values(), key=lambda r: r.created).rid
        req = self.pending.get(rid)
        if req is None:
            raise ServiceValidationError(f"Anfrage {rid} gibt es nicht (mehr)")
        if not req.future.done():
            req.future.set_result({"approved": approve, "von": von, "minutes": minutes,
                                   "down": down, "up": up, "data_mb": data_mb})
        return req.label()


def _ts(value: Any) -> str | None:
    try:
        return dt_util.utc_from_timestamp(int(value)).isoformat()
    except (TypeError, ValueError):
        return None
