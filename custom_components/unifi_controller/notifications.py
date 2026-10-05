"""Benachrichtigungen nach Kategorie an konfigurierbare Empfänger verteilen."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components import persistent_notification as pn
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Kategorie → Anzeigename (Reihenfolge = Reihenfolge im Optionsdialog)
NOTIFY_CATEGORIES: dict[str, str] = {
    "new_device": "Neue Geräte",
    "internet": "Internet",
    "security": "Sicherheit",
    "updates": "Updates",
    "kids": "Kinder",
}
PERSISTENT = "persistent_notification"
# Dienste, die keine eigenen Empfänger sind
SKIP = {"notify", "send_message"}


def option_key(category: str) -> str:
    return f"notify_{category}"


def notify_targets(hass: HomeAssistant) -> dict[str, str]:
    """Verfügbare Empfänger: Dienstname → Anzeigename."""
    out: dict[str, str] = {PERSISTENT: "Home Assistant (Benachrichtigung in HA)"}
    for svc in sorted(hass.services.async_services_for_domain("notify")):
        if svc in SKIP or svc == PERSISTENT:
            continue
        label = svc.removeprefix("mobile_app_").replace("_", " ").title()
        out[svc] = f"{label} ({'App' if svc.startswith('mobile_app_') else svc})"
    return out


async def async_send(hass: HomeAssistant, options: dict[str, Any], category: str,
                     title: str, message: str, data: dict[str, Any] | None = None) -> list[str]:
    """An alle für ``category`` gewählten Empfänger senden; ohne Auswahl → HA-Benachrichtigung."""
    targets = list(options.get(option_key(category)) or [PERSISTENT])
    sent: list[str] = []
    for svc in targets:
        try:
            if svc == PERSISTENT:
                tag = (data or {}).get("tag")
                pn.async_create(hass, message, title=title,
                                notification_id=f"{DOMAIN}_{tag or category}")
            else:
                if not hass.services.has_service("notify", svc):
                    _LOGGER.warning("Benachrichtigungsdienst notify.%s nicht vorhanden", svc)
                    continue
                payload: dict[str, Any] = {"title": title, "message": message}
                if data:
                    payload["data"] = data
                await hass.services.async_call("notify", svc, payload, blocking=True)
            sent.append(svc)
        except Exception as err:  # noqa: BLE001 – ein Empfänger darf die anderen nicht blockieren
            _LOGGER.warning("Benachrichtigung an %s fehlgeschlagen: %s", svc, err)
    return sent
