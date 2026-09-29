"""Neue Geheimnisse erzeugen (WireGuard-Serverschlüssel, WLAN-Passwörter) – nur in HA."""
from __future__ import annotations

import base64
import secrets
import string
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from homeassistant.components import persistent_notification

from .api import UniFiApiError
from .resources import object_name

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

WG_TYPES = {"wireguard-server", "wireguard-client"}


def is_wireguard(net: dict) -> bool:
    return net.get("vpn_type") in WG_TYPES or "x_wireguard_private_key" in net


def generate_wg_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def generate_passphrase(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def _fresh(coordinator: UniFiCoordinator, path: str, obj_id: str) -> dict:
    objs = await coordinator.client.list_objects(path)
    return next((o for o in objs if o.get("_id") == obj_id), {})


async def async_rotate_wireguard(coordinator: UniFiCoordinator, net: dict) -> dict[str, Any]:
    """Neuen Server-Schlüssel setzen; liefert nur den Public Key zurück."""
    if not is_wireguard(net):
        raise UniFiApiError(f"'{object_name(net)}' ist kein WireGuard-VPN")
    priv, pub = generate_wg_keypair()
    await coordinator.async_update_object("networks", net, {"x_wireguard_private_key": priv})
    fresh = await _fresh(coordinator, "rest/networkconf", net["_id"])
    verified = fresh.get("x_wireguard_private_key") == priv
    del priv
    name = object_name(net)
    persistent_notification.async_create(
        coordinator.hass,
        f"Neuer WireGuard-Serverschlüssel für **{name}** gesetzt"
        f"{'' if verified else ' (Kontrolle fehlgeschlagen – bitte im UniFi-UI prüfen)'}.\n\n"
        f"Öffentlicher Schlüssel: `{pub}`\n\n"
        "Alle VPN-Clients brauchen eine neue Konfiguration (UniFi → VPN → Client neu exportieren).",
        title="UniFi: VPN-Schlüssel erneuert",
        notification_id=f"unifi_controller_wg_{net['_id']}",
    )
    return {"network": name, "public_key": pub, "verified": verified}


async def async_rotate_wlan(coordinator: UniFiCoordinator, wlan: dict, length: int,
                            notify: bool) -> dict[str, Any]:
    """Neues WLAN-Passwort; Klartext nur in der Service-Antwort bzw. Benachrichtigung."""
    pw = generate_passphrase(length)
    await coordinator.async_update_object("wlans", wlan, {"x_passphrase": pw})
    fresh = await _fresh(coordinator, "rest/wlanconf", wlan["_id"])
    verified = fresh.get("x_passphrase") == pw
    name = object_name(wlan)
    if notify:
        persistent_notification.async_create(
            coordinator.hass,
            f"Neues Passwort für WLAN **{name}**: `{pw}`\n\n"
            "Alle Geräte in diesem WLAN müssen neu verbunden werden. "
            "Diese Meldung nach dem Notieren löschen.",
            title="UniFi: WLAN-Passwort erneuert",
            notification_id=f"unifi_controller_wlan_{wlan['_id']}",
        )
    return {"wlan": name, "passphrase": pw, "verified": verified}
