"""Logbuch: Sicherheitsereignisse und Fail2Ban-Aktionen mit Klartext."""
from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.logbook import LOGBOOK_ENTRY_MESSAGE, LOGBOOK_ENTRY_NAME
from homeassistant.core import Event, HomeAssistant, callback

from .const import DOMAIN, EVENT_ALERT, EVENT_BAN


@callback
def async_describe_events(
    hass: HomeAssistant,
    async_describe_event: Callable[[str, str, Callable[[Event], dict[str, str]]], None],
) -> None:
    @callback
    def describe_alert(event: Event) -> dict[str, str]:
        d = event.data
        src = f" [{d['src_ip']}]" if d.get("src_ip") else ""
        return {
            LOGBOOK_ENTRY_NAME: f"UniFi {d.get('severity') or ''} {d.get('event') or ''}".strip(),
            LOGBOOK_ENTRY_MESSAGE: f"{d.get('message') or d.get('title') or ''}{src}",
        }

    @callback
    def describe_ban(event: Event) -> dict[str, str]:
        d = event.data
        if d.get("action") == "ban":
            dauer = f"{d['minutes']} min" if d.get("minutes") else "dauerhaft"
            msg = f"hat {d.get('ip')} gesperrt – {d.get('reason')} ({dauer})"
        else:
            msg = f"hat {d.get('ip')} entsperrt"
        return {LOGBOOK_ENTRY_NAME: "UniFi Fail2Ban", LOGBOOK_ENTRY_MESSAGE: msg}

    async_describe_event(DOMAIN, EVENT_ALERT, describe_alert)
    async_describe_event(DOMAIN, EVENT_BAN, describe_ban)
