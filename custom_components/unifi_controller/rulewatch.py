"""Regeländerungen erkennen: Konfiguration zwischen zwei Abrufen vergleichen.

Gemeldet werden hinzugefügte, geänderte und gelöschte Firewall-Policies, Adresslisten,
Traffic-Regeln, Policy-Routen, Portweiterleitungen, statische Routen, DNS-Einträge,
Netze und WLANs – mit Name und den Namen der geänderten Felder, nie mit Werten
(keine Adressen, Passwörter oder Schlüssel).

Der erste Abruf nach dem Start merkt sich nur den Stand. Ein Dataset, das nicht abrufbar
war, wird übersprungen (es enthält dann den alten Stand). Verschwinden alle Objekte eines
Typs auf einmal, wird das erst beim nächsten Abruf geglaubt.
"""
from __future__ import annotations

from collections.abc import Callable
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback

from .const import EVENT_RULE_CHANGE
from .resources import LOCAL_FIELDS, VOLATILE, is_secret, is_system, object_name

_LOGGER = logging.getLogger(__name__)

# dataset → Anzeigename (= rule_type im Ereignis)
WATCHED: dict[str, str] = {
    "firewall_policies": "Firewall-Policy",
    "firewall_groups": "Adressliste",
    "trafficrules": "Traffic-Regel",
    "trafficroutes": "Policy-Route",
    "portforwards": "Portweiterleitung",
    "routes": "Statische Route",
    "dns_records": "DNS-Eintrag",
    "networks": "Netz",
    "wlans": "WLAN",
}
# Felder, die sich ohne Konfigurationsänderung ändern oder nur lokal ergänzt werden
IGNORE = VOLATILE | LOCAL_FIELDS | {
    "metadata", "index", "official_ipv4", "site_id", "attr_hidden_id",
    "dhcpd_start", "dhcpd_stop", "dhcpd_leasetime", "domain_name", "ip_subnet", "dhcpd_enabled",
    "x_iapp_key", "wpa3_transition_initial_setup", "minrate_setting_preference",
}
MAX_PER_POLL = 100


def _clean(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in IGNORE}


def _enabled(obj: dict) -> bool | None:
    val = obj.get("enabled")
    return val if isinstance(val, bool) else None


def diff(old: dict[str, dict], new: dict[str, dict]) -> list[tuple[str, str, dict, list[str]]]:
    """(art, id, objekt, geänderte_felder) – art = added/modified/deleted."""
    out: list[tuple[str, str, dict, list[str]]] = []
    for oid, obj in new.items():
        if is_system(obj):
            continue
        before = old.get(oid)
        if before is None:
            out.append(("added", oid, obj, []))
            continue
        a, b = _clean(before), _clean(obj)
        if a == b:
            continue
        fields = sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))
        # Geheimnisse: nur „Passwort geändert“, nie welcher Wert
        out.append(("modified", oid, obj,
                    ["(geheim)" if is_secret(f) else f for f in fields]))
    for oid, obj in old.items():
        if oid not in new and not is_system(obj):
            out.append(("deleted", oid, obj, []))
    return out


class RuleWatcher:
    """Vergleicht jeden Konfigurationsabruf mit dem vorherigen."""

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self._seen: dict[str, dict[str, dict]] | None = None
        self._empty_once: set[str] = set()
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self.last: list[dict[str, Any]] = []

    @callback
    def async_add_listener(self, cb: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    @callback
    def check(self, config: dict[str, dict[str, dict]], failed: set[str]) -> list[dict[str, Any]]:
        current = {ds: dict(config.get(ds) or {}) for ds in WATCHED}
        if self._seen is None:
            self._seen = current
            return []
        changes: list[dict[str, Any]] = []
        for ds, label in WATCHED.items():
            old, new = self._seen.get(ds, {}), current[ds]
            if ds in failed:
                current[ds] = old
                continue
            if old and not new and ds not in self._empty_once:
                self._empty_once.add(ds)      # erst beim zweiten leeren Ergebnis glauben
                current[ds] = old
                continue
            self._empty_once.discard(ds)
            for kind, oid, obj, fields in diff(old, new):
                changes.append({
                    "aenderung": kind,
                    "typ": label,
                    "dataset": ds,
                    "id": oid,
                    "name": object_name(obj),
                    "aktiv": _enabled(obj),
                    "geaenderte_felder": fields,
                })
        self._seen = current
        if len(changes) > MAX_PER_POLL:
            _LOGGER.warning("%s Regeländerungen auf einmal – nur die ersten %s werden gemeldet",
                            len(changes), MAX_PER_POLL)
            changes = changes[:MAX_PER_POLL]
        for change in changes:
            _LOGGER.info("Regeländerung: %s %s „%s“ %s", change["typ"], change["aenderung"],
                         change["name"], ", ".join(change["geaenderte_felder"]))
            self.hass.bus.async_fire(EVENT_RULE_CHANGE, {"entry_id": self.entry_id, **change})
            for cb in list(self._listeners):
                cb(change)
        if changes:
            self.last = (changes + self.last)[:20]
        return changes
