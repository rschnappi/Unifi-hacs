"""Dashboard-Formulare: alles, was sonst nur per Dienst geht, direkt im Dashboard bedienen.

Jedes Formular besteht aus Entitäten am Controller-Gerät:
- optional einer Auswahl „… laden“ (bestehenden Eintrag in die Felder übernehmen),
- Eingabefeldern (text / select / number),
- Knöpfen für die Aktionen.

Die Aktionen rufen die Dienste dieser Integration auf (eine Logik für Dienst und Dashboard).
Das Ergebnis jeder Aktion steht im Sensor „Letzte Aktion“; Fehler zeigt HA als Meldung an.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Any

from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .dnsform import FORM_TYPES, NEW, TYPE_KEYS, async_delete as dns_delete
from .dnsform import async_set as dns_set, find as dns_find, label as dns_label, records as dns_records
from .resources import DNS_VALUE_FIELD, object_name

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)
SETTLE_S = 1.0


@dataclass
class Field:
    key: str
    name: str
    kind: str                       # text | select | number
    icon: str = "mdi:form-textbox"
    default: Any = ""
    options: Callable[[UniFiCoordinator], list[str]] | list[str] | None = None
    minimum: float = 0
    maximum: float = 100
    step: float = 1
    unit: str | None = None


@dataclass
class Action:
    key: str
    name: str
    icon: str
    run: Callable[[Form], Awaitable[str]]


@dataclass
class Loader:
    name: str
    options: Callable[[UniFiCoordinator], list[str]]
    load: Callable[[Form, str | None], None]          # None = „Neuer Eintrag“
    current: Callable[[Form], str | None]


@dataclass
class FormSpec:
    key: str
    title: str
    fields: list[Field]
    actions: list[Action]
    loader: Loader | None = None
    available: Callable[[UniFiCoordinator], bool] = lambda c: True


class Form:
    """Zustand eines Formulars (Werte der Felder)."""

    def __init__(self, coordinator: UniFiCoordinator, spec: FormSpec) -> None:
        self.c = coordinator
        self.spec = spec
        self.values: dict[str, Any] = {f.key: f.default for f in spec.fields}
        self._listeners: list[tuple[Callable[[], None], str | None]] = []

    def __getitem__(self, key: str) -> Any:
        return self.values.get(key)

    @callback
    def async_add_listener(self, cb: Callable[[], None], key: str | None = None) -> Callable[[], None]:
        """key = nur bei Änderung dieses Felds benachrichtigen (None = bei jeder Änderung)."""
        entry = (cb, key)
        self._listeners.append(entry)
        return lambda: self._listeners.remove(entry)

    @callback
    def changed(self, keys: set[str] | None = None) -> None:
        # Nur betroffene Felder neu schreiben: jedes Neuzeichnen eines Eingabefelds kann am
        # Tablet den Fokus/die Tastatur verspringen lassen.
        for cb, key in list(self._listeners):
            if key is None or keys is None or key in keys:
                cb()

    @callback
    def set(self, **kw: Any) -> None:
        diff = {k for k, v in kw.items() if self.values.get(k) != v}
        if not diff:
            return
        self.values.update(kw)
        self.changed(diff)

    @callback
    def reset(self) -> None:
        self.values = {f.key: f.default for f in self.spec.fields}
        self.changed()

    async def async_run(self, action: Action) -> str:
        # Ein Textfeld schickt seinen Wert erst beim Verlassen. Tippt man direkt aus dem Feld
        # auf den Knopf, kommt der Wert kurz NACH dem Knopfdruck an – darauf warten.
        await asyncio.sleep(SETTLE_S)
        try:
            msg = await action.run(self)
        except (HomeAssistantError, ServiceValidationError) as err:
            self.c.forms_status.report(self.spec.title, f"Fehler: {err}", ok=False)
            raise
        except Exception as err:  # noqa: BLE001 – im Dashboard verständlich melden
            _LOGGER.exception("Formular %s/%s fehlgeschlagen", self.spec.key, action.key)
            self.c.forms_status.report(self.spec.title, f"Fehler: {err}", ok=False)
            raise HomeAssistantError(str(err)) from err
        self.c.forms_status.report(self.spec.title, msg)
        self.changed()
        return msg


class FormStatus:
    """Letzte Aktion über alle Formulare (für den Sensor „Letzte Aktion“)."""

    def __init__(self) -> None:
        self.message = "–"
        self.form = None
        self.ok = True
        self.time = None
        self._listeners: list[Callable[[], None]] = []

    @callback
    def async_add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    @callback
    def report(self, form: str, message: str, ok: bool = True) -> None:
        self.form, self.message, self.ok, self.time = form, message[:250], ok, dt_util.utcnow()
        for cb in list(self._listeners):
            cb()


# ---------------------------------------------------------------- Hilfen

async def _service(form: Form, service: str, data: dict[str, Any], response: bool = False) -> Any:
    hass = form.c.hass
    return await hass.services.async_call(
        DOMAIN, service, {"config_entry_id": form.c.config_entry.entry_id, **data},
        blocking=True, return_response=response)


def _need(form: Form, key: str, what: str) -> str:
    val = str(form[key] or "").strip()
    if not val:
        raise ServiceValidationError(f"{what} fehlt – Eingabe mit Enter bestätigen oder Feld verlassen")
    return val


PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def _ports(val: str, what: str) -> str:
    val = val.replace(" ", "")
    if not PORT_RE.match(val) or any(not 1 <= int(p) <= 65535 for p in re.split(r"[,-]", val)):
        raise ServiceValidationError(f"{what}: Port, Bereich (1000-2000) oder Liste (80,443)")
    return val


def _ip(val: str, what: str) -> str:
    try:
        return str(ipaddress.ip_address(val.strip()))
    except ValueError as err:
        raise ServiceValidationError(f"{what}: „{val}“ ist keine IP-Adresse") from err


# ---------------------------------------------------------------- DNS

def _dns_load(form: Form, option: str | None) -> None:
    rec = next((r for r in dns_records(form.c) if dns_label(r) == option), None)
    if rec is None:
        form.reset()
        return
    form.set(domain=rec["domain"], type=TYPE_KEYS.get(rec["type"], "A"),
             value=str(rec.get(DNS_VALUE_FIELD.get(rec["type"], ""), "") or ""))


def _dns_current(form: Form) -> str | None:
    hits = dns_find(form.c, form["domain"], form["type"]) if form["domain"] else []
    return dns_label(hits[0]) if hits else None


async def _dns_save(form: Form) -> str:
    hits = dns_find(form.c, form["domain"], form["type"]) if form["domain"] else []
    cur = hits[0] if hits else None
    res = await dns_set(form.c, form["domain"], form["type"], form["value"],
                        int(cur.get("ttlSeconds") or 0) if cur else 0,
                        bool(cur.get("enabled", True)) if cur else True)
    return f"DNS {form['domain']} ({form['type']}) → {form['value']} {res['action']}"


async def _dns_delete(form: Form) -> str:
    name = await dns_delete(form.c, form["domain"], form["type"])
    form.reset()
    return f"DNS {name} gelöscht"


DNS = FormSpec(
    "dns", "DNS",
    fields=[Field("domain", "DNS Domain", "text", "mdi:web"),
            Field("type", "DNS Typ", "select", "mdi:format-list-bulleted-type", "A", FORM_TYPES),
            Field("value", "DNS Ziel", "text", "mdi:target")],
    actions=[Action("save", "DNS-Eintrag speichern", "mdi:content-save", _dns_save),
             Action("delete", "DNS-Eintrag löschen", "mdi:delete", _dns_delete)],
    loader=Loader("DNS-Eintrag laden", lambda c: [dns_label(r) for r in dns_records(c)],
                  _dns_load, _dns_current),
)


# ---------------------------------------------------------------- Portweiterleitung

def _pf_all(c: UniFiCoordinator) -> list[dict]:
    return sorted((c.data.config.get("portforwards") or {}).values(),
                  key=lambda o: object_name(o).lower())


def _pf_by_name(c: UniFiCoordinator, name: str) -> dict | None:
    name = (name or "").strip().lower()
    return next((o for o in _pf_all(c) if object_name(o).lower() == name), None)


def _pf_load(form: Form, option: str | None) -> None:
    obj = _pf_by_name(form.c, option or "")
    if obj is None:
        form.reset()
        return
    form.set(name=object_name(obj), dst_port=str(obj.get("dst_port") or ""),
             fwd=str(obj.get("fwd") or ""), fwd_port=str(obj.get("fwd_port") or ""),
             proto=obj.get("proto") or "tcp_udp", src=str(obj.get("src") or "any"))


def _pf_current(form: Form) -> str | None:
    obj = _pf_by_name(form.c, form["name"])
    return object_name(obj) if obj else None


async def _pf_save(form: Form) -> str:
    name = _need(form, "name", "Name")
    dst = _ports(_need(form, "dst_port", "Port außen"), "Port außen")
    fwd = _ip(_need(form, "fwd", "Ziel-IP"), "Ziel-IP")
    fwd_port = _ports(str(form["fwd_port"] or dst).strip(), "Port innen")
    src = str(form["src"] or "any").strip() or "any"
    if src != "any":
        try:
            ipaddress.ip_network(src, strict=False)
        except ValueError as err:
            raise ServiceValidationError(f"Quelle: „{src}“ – „any“, IP oder Netz (CIDR)") from err
    body = {"name": name, "dst_port": dst, "fwd": fwd, "fwd_port": fwd_port,
            "proto": form["proto"] or "tcp_udp", "src": src,
            "src_limiting_enabled": src != "any"}
    if src != "any":
        body["src_limiting_type"] = "ip"
    cur = _pf_by_name(form.c, name)
    if cur:
        await form.c.async_update_object("portforwards", cur, body)
        return f"Portweiterleitung „{name}“ geändert ({dst} → {fwd}:{fwd_port})"
    await form.c.async_create_object("portforwards", {
        **body, "enabled": True, "log": False, "pfwd_interface": "wan"})
    return f"Portweiterleitung „{name}“ angelegt ({dst} → {fwd}:{fwd_port})"


async def _pf_delete(form: Form) -> str:
    cur = _pf_by_name(form.c, form["name"])
    if cur is None:
        raise ServiceValidationError(f"Portweiterleitung „{form['name']}“ nicht gefunden")
    await form.c.async_delete_object("portforwards", cur)
    form.reset()
    return f"Portweiterleitung „{object_name(cur)}“ gelöscht"


PORTFORWARD = FormSpec(
    "portforward", "Portweiterleitung",
    fields=[Field("name", "Portweiterleitung Name", "text", "mdi:rename"),
            Field("dst_port", "Portweiterleitung Port außen", "text", "mdi:import"),
            Field("fwd", "Portweiterleitung Ziel-IP", "text", "mdi:ip-network"),
            Field("fwd_port", "Portweiterleitung Port innen", "text", "mdi:export"),
            Field("proto", "Portweiterleitung Protokoll", "select", "mdi:swap-horizontal",
                  "tcp_udp", ["tcp_udp", "tcp", "udp"]),
            Field("src", "Portweiterleitung Quelle", "text", "mdi:shield-account", "any")],
    actions=[Action("save", "Portweiterleitung speichern", "mdi:content-save", _pf_save),
             Action("delete", "Portweiterleitung löschen", "mdi:delete", _pf_delete)],
    loader=Loader("Portweiterleitung laden", lambda c: [object_name(o) for o in _pf_all(c)],
                  _pf_load, _pf_current),
)


# ---------------------------------------------------------------- WireGuard-Zugänge

def _wg_servers(c: UniFiCoordinator) -> dict[str, dict]:
    from .wireguard import wg_servers  # noqa: PLC0415
    return wg_servers(c)


def _wg_server_names(c: UniFiCoordinator) -> list[str]:
    return sorted(object_name(n) for n in _wg_servers(c).values())


def _wg_users(c: UniFiCoordinator) -> list[tuple[str, dict, dict]]:
    servers = _wg_servers(c)
    out = []
    for u in (c.data.config.get("wg_users") or {}).values():
        srv = servers.get(u.get("network_id"))
        if srv:
            out.append((f"{u.get('name')} ({object_name(srv)})", u, srv))
    return sorted(out, key=lambda t: t[0].lower())


def _vpn_load(form: Form, option: str | None) -> None:
    hit = next((t for t in _wg_users(form.c) if t[0] == option), None)
    if hit is None:
        form.set(name="", server=form["server"])
        return
    form.set(name=hit[1].get("name") or "", server=object_name(hit[2]))


def _vpn_current(form: Form) -> str | None:
    return next((t[0] for t in _wg_users(form.c)
                 if t[1].get("name") == form["name"] and object_name(t[2]) == form["server"]), None)


async def _vpn_create(form: Form) -> str:
    name = _need(form, "name", "Name")
    await _service(form, "create_vpn_client",
                   {"name": name, "vpn": form["server"] or None, "notify": True})
    return f"VPN-Zugang „{name}“ angelegt – Konfiguration und QR-Code in den Benachrichtigungen"


async def _vpn_delete(form: Form) -> str:
    name = _need(form, "name", "Name")
    await _service(form, "delete_vpn_client", {"name": name, "vpn": form["server"] or None})
    form.set(name="")
    return f"VPN-Zugang „{name}“ gelöscht"


def _vpn_spec(c: UniFiCoordinator) -> FormSpec:
    names = _wg_server_names(c)
    return FormSpec(
        "vpn", "VPN-Zugang",
        fields=[Field("name", "VPN-Zugang Name", "text", "mdi:account-key"),
                Field("server", "VPN-Zugang Server", "select", "mdi:vpn",
                      names[0] if names else "", _wg_server_names)],
        actions=[Action("create", "VPN-Zugang anlegen", "mdi:account-plus", _vpn_create),
                 Action("delete", "VPN-Zugang löschen", "mdi:account-remove", _vpn_delete)],
        loader=Loader("VPN-Zugang laden", lambda c: [t[0] for t in _wg_users(c)],
                      _vpn_load, _vpn_current),
        available=lambda c: bool(_wg_servers(c)),
    )


# ---------------------------------------------------------------- Fail2Ban

def _ban_load(form: Form, option: str | None) -> None:
    bans = form.c.logs.bans if form.c.logs else {}
    if option in bans:
        form.set(ip=option, reason=str(bans[option].get("reason") or "manuell"))
    else:
        form.reset()


def _ban_current(form: Form) -> str | None:
    bans = form.c.logs.bans if form.c.logs else {}
    return form["ip"] if form["ip"] in bans else None


async def _ban(form: Form) -> str:
    ip = _ip(_need(form, "ip", "IP"), "IP")
    minutes = int(form["minutes"] or 0)
    await _service(form, "ban_ip", {"ip": ip, "reason": form["reason"] or "manuell",
                                    **({"minutes": minutes} if minutes else {})})
    return f"{ip} gesperrt ({f'{minutes} min' if minutes else 'dauerhaft'})"


async def _unban(form: Form) -> str:
    ip = _ip(_need(form, "ip", "IP"), "IP")
    await _service(form, "unban_ip", {"ip": ip})
    form.reset()
    return f"{ip} entsperrt"


BAN = FormSpec(
    "ban", "Fail2Ban",
    fields=[Field("ip", "Fail2Ban IP", "text", "mdi:ip"),
            Field("minutes", "Fail2Ban Dauer", "number", "mdi:timer-lock", 1440,
                  minimum=0, maximum=525600, step=5, unit="min"),
            Field("reason", "Fail2Ban Grund", "text", "mdi:comment-alert", "manuell")],
    actions=[Action("ban", "IP sperren", "mdi:shield-lock", _ban),
             Action("unban", "IP entsperren", "mdi:shield-lock-open", _unban)],
    loader=Loader("Gesperrte IP laden",
                  lambda c: sorted(c.logs.bans) if c.logs else [], _ban_load, _ban_current),
    available=lambda c: c.logs is not None,
)


# ---------------------------------------------------------------- Gutscheine

async def _voucher_create(form: Form) -> str:
    name = str(form["name"] or "Gast").strip() or "Gast"
    count, hours, guests = int(form["count"] or 1), float(form["hours"] or 24), int(form["guests"] or 1)
    res = await _service(form, "create_vouchers", {
        "name": name, "count": count, "minutes": int(hours * 60), "guest_limit": guests,
        "notify": True}, response=True)
    codes = ", ".join(v["code"] for v in (res or {}).get("vouchers", []))
    return f"{count} Gutschein(e) „{name}“ ({hours:g} h, {guests} Gerät(e)): {codes}"


async def _voucher_cleanup(form: Form) -> str:
    res = await _service(form, "delete_vouchers", {"expired": True}, response=True)
    return f"{(res or {}).get('deleted', 0)} abgelaufene Gutscheine gelöscht"


VOUCHER = FormSpec(
    "voucher", "Gutschein",
    fields=[Field("name", "Gutschein Name", "text", "mdi:ticket-account", "Gast"),
            Field("count", "Gutschein Anzahl", "number", "mdi:counter", 1, minimum=1, maximum=50),
            Field("hours", "Gutschein Dauer", "number", "mdi:timer-sand", 24,
                  minimum=1, maximum=8760, unit="h"),
            Field("guests", "Gutschein Geräte", "number", "mdi:cellphone-link", 1,
                  minimum=1, maximum=20)],
    actions=[Action("create", "Gutschein erzeugen", "mdi:ticket-confirmation", _voucher_create),
             Action("cleanup", "Abgelaufene Gutscheine löschen", "mdi:delete-sweep",
                    _voucher_cleanup)],
)


# ---------------------------------------------------------------- Firmware

FW_TYPES = {"Alle": None, "Access Points": ["ap"], "Switches": ["switch"], "Gateway": ["gateway"]}


async def _fw_plan(form: Form) -> str:
    from homeassistant.components import persistent_notification as pn  # noqa: PLC0415

    types = FW_TYPES.get(form["types"])
    res = await _service(form, "update_devices",
                         {"dry_run": True, **({"device_types": types} if types else {})}, True)
    rows = [r for r in (res or {}).get("reihenfolge", []) if r.get("dabei")]
    if not rows:
        return f"Firmware ({form['types']}): alles aktuell"
    lines = [f"**{len(rows)} Geräte in {res['wellen']} Durchgängen** (Grenzen: {res['grenzen']})", ""]
    for wave in range(1, res["wellen"] + 1):
        names = [f"{r['name']} {r['version']}→{r['neu']}" for r in rows if r.get("welle") == wave]
        lines.append(f"{wave}. " + ", ".join(names))
    pn.async_create(form.c.hass, "\n".join(lines), title=f"Firmware-Plan ({form['types']})",
                    notification_id=f"{DOMAIN}_firmware_plan")
    return f"Firmware ({form['types']}): {len(rows)} Geräte in {res['wellen']} Durchgängen – Plan in den Benachrichtigungen"


async def _fw_start(form: Form) -> str:
    types = FW_TYPES.get(form["types"])
    res = await _service(form, "update_devices",
                         {**({"device_types": types} if types else {})}, True)
    if not (res or {}).get("gestartet"):
        return f"Firmware ({form['types']}): nichts zu tun"
    return f"Firmware ({form['types']}): {res['geraete']} Geräte gestartet, {res['wellen']} Durchgänge"


async def _fw_cancel(form: Form) -> str:
    res = await _service(form, "update_devices", {"cancel": True}, True)
    return f"Firmware: {len((res or {}).get('abgebrochen') or [])} wartende Updates verworfen"


FIRMWARE = FormSpec(
    "firmware", "Firmware",
    fields=[Field("types", "Firmware Gerätetyp", "select", "mdi:devices", "Alle", list(FW_TYPES))],
    actions=[Action("plan", "Firmware-Plan anzeigen", "mdi:clipboard-list", _fw_plan),
             Action("start", "Firmware-Updates starten", "mdi:update", _fw_start),
             Action("cancel", "Firmware-Updates abbrechen", "mdi:cancel", _fw_cancel)],
)


def build_forms(c: UniFiCoordinator) -> dict[str, Form]:
    specs = [DNS, PORTFORWARD, _vpn_spec(c), BAN, VOUCHER, FIRMWARE]
    return {s.key: Form(c, s) for s in specs if s.available(c)}


__all__ = ["NEW", "Action", "Field", "Form", "FormStatus", "build_forms"]
