"""Lokale DNS-Einträge anlegen/ändern/löschen – gemeinsam für Dienste und Dashboard-Formular.

Das Formular besteht aus Entitäten am Controller-Gerät: „DNS-Eintrag laden“ (Auswahl),
„DNS Domain“, „DNS Typ“, „DNS Ziel“ (Eingaben) und den Knöpfen „DNS-Eintrag speichern“
und „DNS-Eintrag löschen“. Damit geht alles direkt im Dashboard, ohne Helfer oder Skripte.
"""
from __future__ import annotations

from collections.abc import Callable
import ipaddress
from typing import TYPE_CHECKING, Any

from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from .api import UniFiApiError
from .resources import DNS_VALUE_FIELD, is_dns, object_name

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

DNS_TYPES = {"A": "A_RECORD", "AAAA": "AAAA_RECORD", "CNAME": "CNAME_RECORD", "MX": "MX_RECORD",
             "TXT": "TXT_RECORD", "SRV": "SRV_RECORD", "FORWARD": "FORWARD_DOMAIN"}
TYPE_KEYS = {v: k for k, v in DNS_TYPES.items()}
FORM_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "FORWARD"]   # SRV braucht Zusatzfelder → Dienst
NEW = "Neuer Eintrag"


def records(c: UniFiCoordinator) -> list[dict]:
    recs = [o for o in (c.data.config.get("dns_records") or {}).values() if is_dns(o)]
    return sorted(recs, key=lambda o: (o["domain"].lower(), o["type"]))


def label(rec: dict) -> str:
    return f"{rec['domain']} ({TYPE_KEYS.get(rec['type'], rec['type'])})"


def find(c: UniFiCoordinator, domain: str, tkey: str | None) -> list[dict]:
    domain = domain.strip().lower().rstrip(".")
    rtype = DNS_TYPES.get(tkey or "")
    return [o for o in records(c)
            if o["domain"].lower() == domain and (rtype is None or o["type"] == rtype)]


def check_value(tkey: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ServiceValidationError("Ziel fehlt")
    try:
        if tkey in ("A", "FORWARD"):
            return str(ipaddress.IPv4Address(value)) if tkey == "A" else str(ipaddress.ip_address(value))
        if tkey == "AAAA":
            return str(ipaddress.IPv6Address(value))
    except ValueError as err:
        raise ServiceValidationError(f"„{value}“ ist keine gültige IP-Adresse für {tkey}") from err
    return value


def check_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not domain or len(domain) > 127 or " " in domain:
        raise ServiceValidationError("Domain ungültig (1–127 Zeichen, keine Leerzeichen)")
    return domain


async def async_set(c: UniFiCoordinator, domain: str, tkey: str, value: str, ttl: int = 0,
                    enabled: bool = True, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Anlegen oder (gleiche Domain + Typ) ändern."""
    if tkey not in DNS_TYPES:
        raise ServiceValidationError(f"Typ {tkey} unbekannt")
    domain = check_domain(domain)
    rtype = DNS_TYPES[tkey]
    body: dict[str, Any] = {"type": rtype, "enabled": enabled, "domain": domain,
                            DNS_VALUE_FIELD[rtype]: check_value(tkey, value)}
    if rtype != "FORWARD_DOMAIN":
        body["ttlSeconds"] = ttl
    body.update(extra or {})
    cur = find(c, domain, tkey)
    try:
        if cur:
            res = await c.async_update_object("dns_records", cur[0], body)
        else:
            res = await c.async_create_object("dns_records", body)
    except UniFiApiError as err:
        raise HomeAssistantError(f"DNS-Eintrag {domain}: {err}") from err
    return {"action": "geändert" if cur else "angelegt", "record": res}


async def async_delete(c: UniFiCoordinator, domain: str, tkey: str | None) -> str:
    hits = find(c, domain, tkey)
    if not hits:
        raise ServiceValidationError(f"Kein DNS-Eintrag für {domain.strip()}")
    if len(hits) > 1 and not tkey:
        raise ServiceValidationError(f"{domain} hat mehrere Einträge – Typ angeben")
    try:
        await c.async_delete_object("dns_records", hits[0])
    except UniFiApiError as err:
        raise HomeAssistantError(f"DNS-Eintrag {domain}: {err}") from err
    return object_name(hits[0])


class DnsForm:
    """Gemeinsamer Zustand der Formular-Entitäten."""

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        self.c = coordinator
        self.domain = ""
        self.tkey = "A"
        self.value = ""
        self._listeners: list[Callable[[], None]] = []

    @callback
    def async_add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    @callback
    def changed(self) -> None:
        for cb in list(self._listeners):
            cb()

    @callback
    def set(self, **kw: Any) -> None:
        for key, val in kw.items():
            setattr(self, key, val)
        self.changed()

    @callback
    def load(self, rec: dict | None) -> None:
        if rec is None:
            self.set(domain="", tkey="A", value="")
            return
        self.set(domain=rec["domain"], tkey=TYPE_KEYS.get(rec["type"], "A"),
                 value=str(rec.get(DNS_VALUE_FIELD.get(rec["type"], ""), "") or ""))

    def current(self) -> dict | None:
        hits = find(self.c, self.domain, self.tkey) if self.domain else []
        return hits[0] if hits else None

    async def async_save(self) -> dict[str, Any]:
        cur = self.current()
        ttl = int(cur.get("ttlSeconds") or 0) if cur else 0
        enabled = bool(cur.get("enabled", True)) if cur else True
        res = await async_set(self.c, self.domain, self.tkey, self.value, ttl, enabled)
        self.changed()
        return res

    async def async_delete(self) -> str:
        name = await async_delete(self.c, self.domain, self.tkey)
        self.load(None)
        return name
