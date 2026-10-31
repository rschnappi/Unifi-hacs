"""Lokale DNS-Einträge anlegen/ändern/löschen – gemeinsam für Dienste und Dashboard-Formular.

Das Dashboard-Formular dazu steht in forms.py.
"""
from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

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


def device_records(c: UniFiCoordinator) -> list[dict[str, Any]]:
    """Lokale DNS-Namen, die direkt an Geräten hängen (feste IP + „Local DNS Record“)."""
    out = []
    for u in (c.data.users if c.data else {}).values():
        name = (u.get("local_dns_record") or "").strip().lower()
        if name:
            out.append({"domain": name, "ip": u.get("fixed_ip") or u.get("last_ip"),
                        "geraet": u.get("name") or u.get("hostname") or u.get("mac"),
                        "aktiv": bool(u.get("local_dns_record_enabled", True))})
    return sorted(out, key=lambda r: r["domain"])


def _api_error(c: UniFiCoordinator, domain: str, err: Exception) -> HomeAssistantError:
    if "overlap-with-local-dns" in str(err):
        dev = next((r for r in device_records(c) if r["domain"] == domain), None)
        if dev:
            return HomeAssistantError(
                f"{domain} ist schon als DNS-Name am Gerät „{dev['geraet']}“ ({dev['ip']}) "
                "eingetragen – dort ändern (UniFi: Gerät → Einstellungen → Local DNS Record)")
        return HomeAssistantError(f"{domain} überschneidet sich mit einem lokalen DNS-Namen "
                                  "(Gerät mit „Local DNS Record“ oder Domain-Name des Netzes)")
    return HomeAssistantError(f"DNS-Eintrag {domain}: {err}")


def find(c: UniFiCoordinator, domain: str, tkey: str | None) -> list[dict]:
    domain = domain.strip().lower().rstrip(".")
    rtype = DNS_TYPES.get(tkey or "")
    return [o for o in records(c)
            if o["domain"].lower() == domain and (rtype is None or o["type"] == rtype)]


def check_value(tkey: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ServiceValidationError("Ziel fehlt – Eingabe mit Enter bestätigen oder Feld verlassen")
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
        raise _api_error(c, domain, err) from err
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
