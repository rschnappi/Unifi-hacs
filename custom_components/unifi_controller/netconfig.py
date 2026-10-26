"""Gateway-Netze über die offizielle API ändern – inkl. IPv4/DHCP (ab Network 11.0.94).

Gemeinsam genutzt vom Dienst ``set_network`` und vom Optionsdialog „Netze“.
Es wird immer das aktuelle Detail-Objekt gelesen, nur die geänderten Felder ersetzt und das
Ganze zurückgeschrieben – nicht genannte Einstellungen bleiben unverändert.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from .api import UniFiApiError
from .resources import HYBRID, LAN_PURPOSES

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

PATH = HYBRID["networks"]
READ_ONLY = {"id", "metadata", "default"}

# flache Felder (Dienst/Dialog) → Pfad im offiziellen Objekt
FIELDS: dict[str, tuple[str, ...]] = {
    "name": ("name",),
    "enabled": ("enabled",),
    "vlan": ("vlanId",),
    "internet_access": ("internetAccessEnabled",),
    "isolation": ("isolationEnabled",),
    "mdns": ("mdnsForwardingEnabled",),
    "cellular_backup": ("cellularBackupEnabled",),
    "gateway_ip": ("ipv4Configuration", "hostIpAddress"),
    "prefix_length": ("ipv4Configuration", "prefixLength"),
    "auto_scale": ("ipv4Configuration", "autoScaleEnabled"),
    "dhcp_start": ("ipv4Configuration", "dhcpConfiguration", "ipAddressRange", "start"),
    "dhcp_stop": ("ipv4Configuration", "dhcpConfiguration", "ipAddressRange", "stop"),
    "lease_time": ("ipv4Configuration", "dhcpConfiguration", "leaseTimeSeconds"),
    "domain_name": ("ipv4Configuration", "dhcpConfiguration", "domainName"),
    "ping_conflict_detection": (
        "ipv4Configuration", "dhcpConfiguration", "pingConflictDetectionEnabled"),
}
DHCP_FIELDS = {"dhcp_start", "dhcp_stop", "lease_time", "domain_name", "ping_conflict_detection"}
SUBNET_FIELDS = {"gateway_ip", "prefix_length"}


class NetworkConfigError(UniFiApiError):
    """Ungültige Eingabe; ``key`` = Übersetzungsschlüssel für den Dialog."""

    def __init__(self, key: str, message: str) -> None:
        super().__init__(message)
        self.key = key


def _get(obj: dict, path: tuple[str, ...]) -> Any:
    for part in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def _set(obj: dict, path: tuple[str, ...], value: Any) -> None:
    for part in path[:-1]:
        obj = obj.setdefault(part, {})
    obj[path[-1]] = value


def flatten(official: dict) -> dict[str, Any]:
    """Offizielles Netz → flache Werte (für Dialog-Vorgaben und Antworten)."""
    out = {k: _get(official, p) for k, p in FIELDS.items()}
    out["dhcp_mode"] = _get(official, ("ipv4Configuration", "dhcpConfiguration", "mode"))
    return out


def gateway_networks(coordinator: UniFiCoordinator) -> dict[str, str]:
    """external_id → Name aller LAN-/Gast-Netze, die offiziell änderbar sind."""
    nets = (coordinator.data.config.get("networks", {}) if coordinator.data else {})
    return {
        n["external_id"]: n.get("name") or n["external_id"]
        for n in sorted(nets.values(), key=lambda n: (n.get("vlan") or 0, n.get("name") or ""))
        if n.get("external_id") and n.get("purpose") in LAN_PURPOSES
    }


def resolve(coordinator: UniFiCoordinator, ident: str) -> str:
    """Name, interne oder offizielle ID → offizielle ID."""
    key = ident.strip()
    nets = (coordinator.data.config.get("networks", {}) if coordinator.data else {})
    for nid, n in nets.items():
        if key in (nid, n.get("external_id")) or (n.get("name") or "").lower() == key.lower():
            if not n.get("external_id") or n.get("purpose") not in LAN_PURPOSES:
                raise NetworkConfigError("not_gateway", f"{n.get('name')}: kein LAN-/Gast-Netz")
            return n["external_id"]
    raise NetworkConfigError("unknown_network", f"Netz „{ident}“ nicht gefunden")


def other_subnets(coordinator: UniFiCoordinator, ext_id: str) -> dict[str, ipaddress.IPv4Network]:
    """Subnetze aller anderen Netze (auch VPN/WireGuard) – für die Überschneidungsprüfung."""
    out: dict[str, ipaddress.IPv4Network] = {}
    nets = (coordinator.data.config.get("networks", {}) if coordinator.data else {})
    for n in nets.values():
        if n.get("external_id") == ext_id or not n.get("ip_subnet"):
            continue
        try:
            out[n.get("name") or "?"] = ipaddress.ip_interface(n["ip_subnet"]).network
        except ValueError:
            continue
    return out


async def async_read(coordinator: UniFiCoordinator, ext_id: str) -> dict:
    current = await coordinator.client.integration("GET", f"{PATH}/{ext_id}")
    if not isinstance(current, dict) or current.get("management") != "GATEWAY":
        raise NetworkConfigError("not_gateway", "Netz wird nicht vom Gateway verwaltet")
    return current


def validate(current: dict, changes: dict[str, Any], confirm_subnet: bool,
             others: dict[str, ipaddress.IPv4Network] | None = None) -> dict[str, Any]:
    """Prüft die gewünschte Endkonfiguration; liefert die tatsächlich geänderten Felder."""
    before = flatten(current)
    changed = {k: v for k, v in changes.items()
               if k in FIELDS and v is not None and v != before.get(k)}
    after = before | changed

    vlan = after.get("vlan")
    if "vlan" in changed and current.get("default"):
        raise NetworkConfigError("default_vlan", "Das Standardnetz behält VLAN 1")
    if "vlan" in changed and not (2 <= int(vlan) <= 4009):
        raise NetworkConfigError("invalid_vlan", "VLAN muss zwischen 2 und 4009 liegen")

    if not (SUBNET_FIELDS | DHCP_FIELDS) & changed.keys():
        return changed
    if SUBNET_FIELDS & changed.keys() and not confirm_subnet:
        raise NetworkConfigError(
            "confirm_subnet",
            "Subnetz-Änderung trennt alle Geräte im Netz kurz – bitte ausdrücklich bestätigen")
    try:
        iface = ipaddress.ip_interface(f"{after['gateway_ip']}/{int(after['prefix_length'])}")
    except (TypeError, ValueError) as err:
        raise NetworkConfigError("invalid_gateway", "Gateway-IP/Präfix ungültig") from err
    net = iface.network
    if not 8 <= net.prefixlen <= 30 or iface.ip in (net.network_address, net.broadcast_address):
        raise NetworkConfigError("invalid_gateway", "Gateway-IP/Präfix ungültig")
    if SUBNET_FIELDS & changed.keys():
        for other_name, other in (others or {}).items():
            if net.overlaps(other):
                raise NetworkConfigError(
                    "subnet_overlap", f"{net} überschneidet sich mit {other_name} ({other})")

    if before.get("dhcp_mode") not in (None, "SERVER") and DHCP_FIELDS & changed.keys():
        raise NetworkConfigError(
            "dhcp_not_server", "DHCP-Bereich nur änderbar, wenn das Gateway DHCP-Server ist")
    if after.get("dhcp_start") or after.get("dhcp_stop"):
        try:
            start = ipaddress.ip_address(after["dhcp_start"])
            stop = ipaddress.ip_address(after["dhcp_stop"])
        except (TypeError, ValueError) as err:
            raise NetworkConfigError("invalid_range", "DHCP-Bereich ungültig") from err
        hosts = (net.network_address, net.broadcast_address)
        if (start not in net or stop not in net or start > stop
                or start in hosts or stop in hosts):
            raise NetworkConfigError("invalid_range", f"DHCP-Bereich muss in {net} liegen")
        if start <= iface.ip <= stop:
            raise NetworkConfigError("gateway_in_range",
                                     "Gateway-IP darf nicht im DHCP-Bereich liegen")
    if "lease_time" in changed and not 60 <= int(after["lease_time"]) <= 31_536_000:
        raise NetworkConfigError("invalid_lease", "Lease-Zeit 60 s … 1 Jahr")
    return changed


def build_body(current: dict, changed: dict[str, Any]) -> dict:
    body = {k: v for k, v in current.items() if k not in READ_ONLY}
    body = _deepcopy(body)
    for key, value in changed.items():
        if key in ("vlan", "prefix_length", "lease_time"):
            value = int(value)
        _set(body, FIELDS[key], value)
    return body


def _deepcopy(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _deepcopy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deepcopy(v) for v in obj]
    return obj


async def async_set_network(coordinator: UniFiCoordinator, ident: str, changes: dict[str, Any],
                            confirm_subnet: bool = False) -> dict[str, Any]:
    """Netz ändern; liefert {name, geaendert, vorher, jetzt}."""
    ext_id = resolve(coordinator, ident)
    current = await async_read(coordinator, ext_id)
    changed = validate(current, changes, confirm_subnet, other_subnets(coordinator, ext_id))
    if not changed:
        return {"name": current.get("name"), "geaendert": {}, "jetzt": flatten(current)}
    before = flatten(current)
    coordinator.invalidate_ipv4()   # der Abruf nach dem Schreiben liest IPv4/DHCP neu
    result = await coordinator.async_command(
        coordinator.client.integration("PUT", f"{PATH}/{ext_id}", build_body(current, changed)))
    now = flatten(result) if isinstance(result, dict) else before | changed
    _LOGGER.info("Netz %s geändert: %s", current.get("name"),
                 {k: f"{before.get(k)} → {v}" for k, v in changed.items()})
    return {"name": now.get("name") or current.get("name"),
            "geaendert": {k: {"vorher": before.get(k), "jetzt": now.get(k)} for k in changed},
            "jetzt": now}
