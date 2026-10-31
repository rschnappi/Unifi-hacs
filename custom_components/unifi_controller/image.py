"""Bild-Entitäten: QR-Code je WLAN zum Verbinden (Kamera-App scannen).

Der QR-Code enthält das WLAN-Passwort. Deshalb sind nur Gast-WLANs von Haus aus aktiv;
alle anderen gibt es deaktiviert und man schaltet sie bei Bedarf in HA frei.
WPA-Enterprise (RADIUS) bekommt keinen Code – dort gibt es kein gemeinsames Passwort.
"""
from __future__ import annotations

import hashlib
import io

from homeassistant.components.image import ImageEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, async_add_dynamic


def _esc(text: str) -> str:
    for ch in ("\\", ";", ",", ":", '"'):
        text = text.replace(ch, "\\" + ch)
    return text


def wifi_payload(wlan: dict) -> str | None:
    """WIFI:-URI nach ZXing-Schema; None für WPA-Enterprise/unbekannte Sicherheit."""
    security = (wlan.get("security") or "").lower()
    ssid = wlan.get("name") or ""
    if not ssid or security in ("wpaeap", "wep"):
        return None
    hidden = "H:true;" if wlan.get("hide_ssid") else ""
    if security == "open":
        return f"WIFI:T:nopass;S:{_esc(ssid)};{hidden};"
    pw = wlan.get("x_passphrase")
    if not pw:
        return None
    return f"WIFI:T:WPA;S:{_esc(ssid)};P:{_esc(pw)};{hidden};"


def render_png(payload: str) -> bytes:
    import segno  # noqa: PLC0415

    buf = io.BytesIO()
    segno.make(payload, error="m").save(buf, kind="png", scale=8, border=2)
    return buf.getvalue()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        for wid, wlan in coordinator.data.config.get("wlans", {}).items():
            if (wlan.get("security") or "").lower() not in ("wpaeap", "wep"):
                yield WlanQr(hass, coordinator, wid)

    async_add_dynamic(coordinator, async_add_entities, factory)


class WlanQr(ControllerEntity, ImageEntity):
    """QR-Code zum Verbinden mit einem WLAN."""

    _attr_content_type = "image/png"
    _attr_icon = "mdi:qrcode"

    def __init__(self, hass: HomeAssistant, coordinator: UniFiCoordinator, wid: str) -> None:
        wlan = coordinator.data.config["wlans"][wid]
        ControllerEntity.__init__(self, coordinator, f"wlan_qr_{wid}", f"WLAN {wlan.get('name')} QR-Code")
        ImageEntity.__init__(self, hass)
        self._wid = wid
        self._attr_entity_registry_enabled_default = bool(wlan.get("is_guest"))
        self._hash: str | None = None
        self._png: bytes | None = None
        self._update_hash()

    @property
    def _wlan(self) -> dict | None:
        return self.coordinator.data.config.get("wlans", {}).get(self._wid)

    def _payload(self) -> str | None:
        return wifi_payload(self._wlan) if self._wlan else None

    def _update_hash(self) -> None:
        payload = self._payload()
        digest = hashlib.sha256(payload.encode()).hexdigest() if payload else None
        if digest != self._hash:
            self._hash = digest
            self._png = None
            self._attr_image_last_updated = dt_util.utcnow()

    @property
    def available(self) -> bool:
        return super().available and self._payload() is not None

    @property
    def extra_state_attributes(self) -> dict:
        wlan = self._wlan or {}
        return {"ssid": wlan.get("name"), "gast": bool(wlan.get("is_guest")),
                "aktiv": wlan.get("enabled", True), "versteckt": bool(wlan.get("hide_ssid"))}

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_hash()
        super()._handle_coordinator_update()

    async def async_image(self) -> bytes | None:
        payload = self._payload()
        if payload is None:
            return None
        if self._png is None:
            self._png = await self.hass.async_add_executor_job(render_png, payload)
        return self._png
