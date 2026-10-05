"""Logbuch: jeder UniFi-Log-Eintrag, Sicherheitsereignisse und Fail2Ban-Aktionen im Klartext.

HA zeigt in der Aktivitätsliste („Über …“) und unter „Was ist passiert“ den *Namen* des
auslösenden Ereignisses – deshalb steht die verständliche Zusammenfassung im Namen,
die Rohmeldung als Nachricht.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.components.logbook import (
    LOGBOOK_ENTRY_ICON,
    LOGBOOK_ENTRY_MESSAGE,
    LOGBOOK_ENTRY_NAME,
)
from homeassistant.core import Event, HomeAssistant, callback

from .const import DOMAIN, EVENT_ALERT, EVENT_BAN, EVENT_LOG, EVENT_PRESENCE

ICONS = {
    "BLOCKED_BY_FIREWALL": "mdi:wall-fire",
    "THREAT_BLOCKED": "mdi:shield-bug",
    "THREAT_DETECTED": "mdi:shield-alert",
    "HA_LOGIN_FAILED": "mdi:account-alert",
    "ADMIN_ACCESS": "mdi:account-key",
    "ADMIN_LOGIN": "mdi:account-key",
}
CATEGORY_ICONS = {
    "SECURITY": "mdi:shield-outline",
    "CLIENT_DEVICES": "mdi:devices",
    "AUDIT": "mdi:clipboard-text-search",
    "DEVICES": "mdi:access-point",
    "VPN": "mdi:vpn",
    "INTERNET": "mdi:web",
    "SYSTEM": "mdi:cog",
    "UPDATES": "mdi:update",
}


def _who(name: Any, ip: Any) -> str:
    if name and ip and str(name) != str(ip):
        return f"{name} ({ip})"
    return str(name or ip or "?")


def summarize(d: dict[str, Any]) -> str:
    """Einzeilige, verständliche Zusammenfassung eines Log-Eintrags."""
    event = (d.get("event") or "").upper()
    src = _who(d.get("client"), d.get("src_ip"))
    dst = _who(d.get("device"), d.get("dst_ip"))
    policy = d.get("policy")
    if event == "BLOCKED_BY_FIREWALL":
        text = f"Firewall: {src} → {dst} geblockt"
        return f"{text} (Regel „{policy}“)" if policy else text
    if event.startswith("THREAT"):
        verb = "geblockt" if event == "THREAT_BLOCKED" else "erkannt"
        return f"IPS: Angriff von {src} auf {dst} {verb}"
    if event == "HA_LOGIN_FAILED":
        return f"HA-Anmeldung fehlgeschlagen von {src}"
    if event.startswith("CLIENT_CONNECTED"):
        net = f" (Netz {d['network']})" if d.get("network") else ""
        return f"Client verbunden: {src}{net}"
    if event.startswith("CLIENT_DISCONNECTED"):
        return f"Client getrennt: {src}"
    if event.startswith("CLIENT_ROAM"):
        return f"Client gewechselt: {src} → {dst}"
    msg = (d.get("message") or d.get("title") or event or "UniFi-Ereignis").strip()
    return msg[:200]


def details(d: dict[str, Any]) -> str:
    parts = [d.get("message") or ""]
    if d.get("severity"):
        parts.append(f"Schwere: {d['severity']}")
    if d.get("network"):
        parts.append(f"Netz: {d['network']}")
    if d.get("client_mac"):
        parts.append(f"MAC: {d['client_mac']}")
    parts.append(f"{d.get('category') or ''} {d.get('event') or ''}".strip())
    return " · ".join(p for p in parts if p)


def icon(d: dict[str, Any]) -> str:
    return (ICONS.get((d.get("event") or "").upper())
            or CATEGORY_ICONS.get((d.get("category") or "").upper(), "mdi:text-box-search"))


@callback
def async_describe_events(
    hass: HomeAssistant,
    async_describe_event: Callable[[str, str, Callable[[Event], dict[str, str]]], None],
) -> None:
    @callback
    def describe_log(event: Event) -> dict[str, str]:
        d = event.data
        return {LOGBOOK_ENTRY_NAME: summarize(d), LOGBOOK_ENTRY_MESSAGE: details(d),
                LOGBOOK_ENTRY_ICON: icon(d)}

    @callback
    def describe_alert(event: Event) -> dict[str, str]:
        d = event.data
        return {LOGBOOK_ENTRY_NAME: f"⚠ {summarize(d)}", LOGBOOK_ENTRY_MESSAGE: details(d),
                LOGBOOK_ENTRY_ICON: icon(d)}

    @callback
    def describe_ban(event: Event) -> dict[str, str]:
        d = event.data
        if d.get("action") == "ban":
            dauer = f"{d['minutes']} min" if d.get("minutes") else "dauerhaft"
            name = f"Fail2Ban: {d.get('ip')} gesperrt ({dauer})"
            msg = str(d.get("reason") or "")
            ico = "mdi:shield-lock"
        else:
            name = f"Fail2Ban: {d.get('ip')} entsperrt"
            msg = ""
            ico = "mdi:shield-lock-open"
        return {LOGBOOK_ENTRY_NAME: name, LOGBOOK_ENTRY_MESSAGE: msg, LOGBOOK_ENTRY_ICON: ico}

    @callback
    def describe_presence(event: Event) -> dict[str, str]:
        d = event.data
        arrived = d.get("state") == "arrived"
        name = f"{d.get('person')} {'ist angekommen' if arrived else 'ist gegangen'}"
        if arrived and d.get("room") and d["room"] not in ("Zuhause", "Abwesend"):
            name += f" ({d['room']})"
        return {LOGBOOK_ENTRY_NAME: name, LOGBOOK_ENTRY_MESSAGE: str(d.get("reason") or ""),
                LOGBOOK_ENTRY_ICON: "mdi:home-account" if arrived else "mdi:home-export-outline"}

    async_describe_event(DOMAIN, EVENT_LOG, describe_log)
    async_describe_event(DOMAIN, EVENT_PRESENCE, describe_presence)
    async_describe_event(DOMAIN, EVENT_ALERT, describe_alert)
    async_describe_event(DOMAIN, EVENT_BAN, describe_ban)
