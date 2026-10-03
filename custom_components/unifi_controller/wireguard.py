"""WireGuard-VPN-Clients (Zugänge) anlegen/löschen – Schlüssel entstehen in HA, Konfig + QR."""
from __future__ import annotations

import base64
import ipaddress
import os
import secrets
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from homeassistant.components import persistent_notification as pn
from homeassistant.util import slugify

from .api import UniFiApiError
from .resources import object_name
from .secrets_mgmt import generate_wg_keypair

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

QR_DIR = "www/unifi_controller_vpn"
QR_TTL_S = 900          # QR-Bild nach 15 min automatisch löschen (enthält den Private Key)
DEFAULT_ALLOWED_IPS = "0.0.0.0/0, ::/0"


def wg_servers(coordinator: UniFiCoordinator) -> dict[str, dict]:
    return {
        nid: n for nid, n in coordinator.data.config.get("networks", {}).items()
        if n.get("vpn_type") == "wireguard-server"
    }


def users_of(coordinator: UniFiCoordinator, net_id: str) -> list[dict]:
    return [u for u in coordinator.data.config.get("wg_users", {}).values()
            if u.get("network_id") == net_id]


def _server(coordinator: UniFiCoordinator, vpn: str | None) -> dict:
    servers = wg_servers(coordinator)
    if not servers:
        raise UniFiApiError("Kein WireGuard-Server im Controller")
    if not vpn:
        if len(servers) > 1:
            raise UniFiApiError("Mehrere WireGuard-Server – 'vpn' angeben")
        return next(iter(servers.values()))
    for nid, n in servers.items():
        if vpn in (nid, object_name(n)) or object_name(n).lower() == vpn.lower():
            return n
    raise UniFiApiError(f"WireGuard-Server '{vpn}' nicht gefunden")


def _server_public_key(net: dict) -> str:
    priv = net.get("x_wireguard_private_key")
    if not priv:
        raise UniFiApiError("Server-Schlüssel nicht lesbar (API-Key ohne Admin-Rechte?)")
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def _next_ip(net: dict, used: set[str]) -> str:
    iface = ipaddress.ip_interface(net["ip_subnet"])
    for host in iface.network.hosts():
        ip = str(host)
        if ip != str(iface.ip) and ip not in used:
            return ip
    raise UniFiApiError("Keine freie VPN-Adresse mehr im Subnetz")


def _endpoint(coordinator: UniFiCoordinator, net: dict, endpoint: str | None) -> str:
    host = endpoint or coordinator.vpn_endpoint or coordinator.data.health.get(
        "wan", {}).get("wan_ip")
    if not host:
        raise UniFiApiError("Kein Endpunkt bekannt – 'endpoint' angeben (z. B. vpn.example.com)")
    return host if ":" in host.split("]")[-1] else f"{host}:{net.get('local_port', 51820)}"


def _write_qr(hass_config_dir: str, text: str) -> str:
    import segno  # noqa: PLC0415 – Abhängigkeit aus manifest.json

    folder = os.path.join(hass_config_dir, QR_DIR)
    os.makedirs(folder, exist_ok=True)
    name = f"{secrets.token_urlsafe(24)}.png"
    segno.make(text, error="m").save(os.path.join(folder, name), scale=6, border=2)
    return name


def _delete(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


async def async_create_client(coordinator: UniFiCoordinator, *, name: str, vpn: str | None,
                              allowed_ips: str | None, dns: str | None, endpoint: str | None,
                              notify: bool) -> dict[str, Any]:
    hass = coordinator.hass
    net = _server(coordinator, vpn)
    if any(u.get("name") == name for u in users_of(coordinator, net["_id"])):
        raise UniFiApiError(f"VPN-Zugang '{name}' existiert bereits")
    used = {u.get("interface_ip") for u in users_of(coordinator, net["_id"])}
    ip = _next_ip(net, used)
    priv, pub = generate_wg_keypair()
    server_pub = _server_public_key(net)
    await coordinator.async_command(coordinator.client.request(
        "POST", f"v2/wireguard/{net['_id']}/users/batch",
        [{"name": name, "interface_ip": ip, "public_key": pub}]))
    gw = str(ipaddress.ip_interface(net["ip_subnet"]).ip)
    config = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {ip}/32\n"
        f"DNS = {dns or gw}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"AllowedIPs = {allowed_ips or DEFAULT_ALLOWED_IPS}\n"
        f"Endpoint = {_endpoint(coordinator, net, endpoint)}\n"
        "PersistentKeepalive = 25\n"
    )
    del priv
    qr_url = None
    if notify:
        fname = await hass.async_add_executor_job(_write_qr, hass.config.config_dir, config)
        path = os.path.join(hass.config.config_dir, QR_DIR, fname)
        qr_url = f"/local/unifi_controller_vpn/{fname}"
        hass.loop.call_later(
            QR_TTL_S, lambda: hass.async_add_executor_job(_delete, path))
        pn.async_create(
            hass,
            f"Neuer VPN-Zugang **{name}** ({ip}) auf **{object_name(net)}**.\n\n"
            f"In der WireGuard-App scannen (Bild wird nach {QR_TTL_S // 60} min gelöscht):\n\n"
            f"![QR]({qr_url})\n\n```\n{config}```\n\n"
            "⚠️ Enthält den privaten Schlüssel – diese Benachrichtigung nach dem Einrichten schließen.",
            title="UniFi: VPN-Zugang angelegt",
            notification_id=f"unifi_controller_vpn_{slugify(name)}",
        )
    return {"name": name, "ip": ip, "public_key": pub, "network": object_name(net),
            "qr_url": qr_url, "config": config}


async def async_delete_client(coordinator: UniFiCoordinator, *, name: str,
                              vpn: str | None) -> dict[str, Any]:
    net = _server(coordinator, vpn)
    users = [u for u in users_of(coordinator, net["_id"])
             if name in (u.get("_id"), u.get("name"))]
    if len(users) != 1:
        raise UniFiApiError(f"VPN-Zugang '{name}' " + ("mehrdeutig" if users else "nicht gefunden"))
    await coordinator.async_command(coordinator.client.request(
        "POST", f"v2/wireguard/{net['_id']}/users/batch_delete", [users[0]["_id"]]))
    return {"deleted": users[0].get("name"), "ip": users[0].get("interface_ip")}
