"""Länder-Blocking über Zonen-Firewall-Policies (mit Ausnahmen) – offizielle UniFi-API.

Pro Zielzone (z. B. die Zone mit der HA-Portweiterleitung) werden drei Policies gepflegt,
in genau dieser Reihenfolge (UniFi wertet pro Zonenpaar nach Index aus, neue Policies
landen hinten):

  1. Länder-Ausnahmen -> <Zone> erlauben   (Traffic Matching List „HA Länder-Ausnahmen“)
  2. Länder erlauben -> <Zone>             (Quelle = erlaubte Länder)
  3. Länder-Blocking External -> <Zone> (Rest blocken)   (nur NEUE Verbindungen)

Optional dasselbe für WireGuard am Gateway (nur der WireGuard-Port, damit IPv6-RA,
DHCPv6 und IPTV vom Provider nicht getroffen werden). Das globale UniFi-„Region
Blocking“ (usg_geo) wird bewusst NICHT verwendet – es kennt keine Ausnahmen.
"""
from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

from .api import UniFiApiError
from .countries import COUNTRIES
from .resources import is_system

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator, UniFiData

EXC_GROUP = "HA Länder-Ausnahmen"
DEFAULT_EXCEPTIONS = ["160.79.104.0/21"]   # Anthropic/Claude (MCP-Connector)
PLACEHOLDER = "192.0.2.1"
INVALID_CODES = {"AN"}                     # früher von stat/ccode gelistet, von Policies abgelehnt
FW = "firewall_policies"
LISTS = "firewall_groups"                  # offizielle API: Traffic Matching Lists
WG_NAME = "WireGuard"

P_EXC = "Länder-Ausnahmen -> {} erlauben"
P_ALLOW = "Länder erlauben -> {}"
P_BLOCK = "Länder-Blocking External -> {} (Rest blocken)"


# ------------------------------------------------------------------ Zonen
def _zones(data: UniFiData) -> dict[str, dict]:
    return data.config.get("firewall_zones", {}) if data else {}


def zone_id(data: UniFiData, key: str) -> str | None:
    """ID (offizielle API) der Zone mit diesem Namen (ohne Groß-/Kleinschreibung)."""
    for zid, z in _zones(data).items():
        if (z.get("name") or "").lower() == key:
            return zid
    return None


def zone_of_network(data: UniFiData, net: dict) -> str | None:
    """Offizielle Zonen-ID eines (internen) Netzes."""
    legacy = net.get("firewall_zone_id")
    for zid, z in _zones(data).items():
        if legacy and z.get("internal_zone_id") == legacy:
            return zid
        if net.get("external_id") in (z.get("networkIds") or []):
            return zid
    return None


def legacy_zone_id(data: UniFiData, zid: str | None) -> str | None:
    """Interne Zonen-ID (für rest/networkconf) zur offiziellen Zone."""
    return (_zones(data).get(zid or "") or {}).get("internal_zone_id")


def target_zones(data: UniFiData) -> dict[str, str]:
    """Auswählbare Zielzonen (ohne External/Gateway/VPN): id -> Name."""
    skip = {zone_id(data, "external"), zone_id(data, "gateway"), zone_id(data, "vpn")}
    return {zid: z.get("name", zid) for zid, z in _zones(data).items() if zid not in skip}


# ------------------------------------------------------------------ Lesen
def _policies(data: UniFiData) -> list[dict]:
    return list(data.config.get(FW, {}).values()) if data else []


def _find(data: UniFiData, prefix: str, dest_zone: str) -> dict | None:
    for p in _policies(data):
        if (not is_system(p) and (p.get("name") or "").startswith(prefix)
                and (p.get("destination") or {}).get("zoneId") == dest_zone):
            return p
    return None


def _group(data: UniFiData) -> dict | None:
    for g in (data.config.get(LISTS, {}) if data else {}).values():
        if g.get("name") == EXC_GROUP:
            return g
    return None


def list_members(group: dict | None) -> list[str]:
    return [str(i.get("value")) for i in (group or {}).get("items") or [] if i.get("value")]


def list_items(members: list[str]) -> list[dict[str, str]]:
    """Adressen/Netze → Einträge einer IPv4-Traffic-Matching-List."""
    out = []
    for m in members:
        net = ipaddress.ip_network(m, strict=False)
        if net.version != 4:
            raise UniFiApiError(f"Nur IPv4 möglich: {m}")
        out.append({"type": "IP_ADDRESS", "value": str(net.network_address)}
                   if net.prefixlen == 32 else {"type": "SUBNET", "value": str(net)})
    return out


def _regions(policy: dict | None) -> list[str]:
    tf = ((policy or {}).get("source") or {}).get("trafficFilter") or {}
    return list((tf.get("regionFilter") or {}).get("regions") or [])


def state(data: UniFiData) -> dict[str, Any]:
    """Aktueller Stand aus den Policies ablesen."""
    zones = target_zones(data)
    gw = zone_id(data, "gateway")
    active: list[str] = []
    countries: set[str] = set()
    enabled = False
    for zid in zones:
        block = _find(data, P_BLOCK.format(zones[zid]), zid)
        allow = _find(data, P_ALLOW.format(zones[zid]), zid)
        if block:
            active.append(zid)
            enabled = enabled or bool(block.get("enabled"))
        countries |= set(_regions(allow))
    wg_block = _find(data, P_BLOCK.format(WG_NAME), gw) if gw else None
    if gw:
        countries |= set(_regions(_find(data, P_ALLOW.format(WG_NAME), gw)))
    group = _group(data)
    exceptions = [m for m in list_members(group) if m != PLACEHOLDER]
    return {
        "enabled": enabled or bool(wg_block and wg_block.get("enabled")),
        "countries": sorted(countries),
        "zones": active,
        "zone_names": [zones[z] for z in active],
        "wireguard": wg_block is not None,
        "exceptions": exceptions if group else list(DEFAULT_EXCEPTIONS),
    }


def country_names(codes: list[str]) -> list[str]:
    return [f"{COUNTRIES.get(c, c)} ({c})" for c in codes]


async def async_country_codes(coordinator: UniFiCoordinator) -> dict[str, str]:
    """Vom Controller unterstützte Ländercodes (offizielle API), deutsche Namen wo bekannt."""
    data = await coordinator.client.integration_list("countries")
    return {
        c["code"]: COUNTRIES.get(c["code"], c.get("name", c["code"]))
        for c in data if c.get("code") and c["code"] not in INVALID_CODES
    }


# ------------------------------------------------------------------ Schreiben
def _base(name: str, dest: str, src_zone: str, action: str, desc: str,
          allow_return: bool = False) -> dict[str, Any]:
    act: dict[str, Any] = {"type": action}
    if action == "ALLOW":
        act["allowReturnTraffic"] = allow_return
    return {
        "enabled": True, "name": name, "description": desc, "action": act,
        "source": {"zoneId": src_zone}, "destination": {"zoneId": dest},
        "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
        "loggingEnabled": False,
    }


def _wg_port(data: UniFiData) -> int:
    for n in data.config.get("networks", {}).values():
        if n.get("vpn_type") == "wireguard-server" and n.get("local_port"):
            return int(n["local_port"])
    return 51820


def _desired(data: UniFiData, zid: str, zname: str, ext: str, countries: list[str],
             enabled: bool, group_id: str, wireguard: bool) -> list[tuple[str, dict]]:
    """Soll-Policies in Reihenfolge (Präfix, Body im Schema der offiziellen API)."""
    out: list[tuple[str, dict]] = []
    if not wireguard:
        exc = _base(P_EXC.format(zname), zid, ext, "ALLOW",
                    "Ausnahmen vom Länder-Blocking (UniFi Controller Manager)", True)
        exc["ipProtocolScope"] = {"ipVersion": "IPV4"}
        exc["source"]["trafficFilter"] = {"type": "IP_ADDRESS", "ipAddressFilter": {
            "type": "TRAFFIC_MATCHING_LIST", "matchOpposite": False,
            "trafficMatchingListId": group_id}}
        out.append((P_EXC.format(zname), exc))
    allow = _base(f"{P_ALLOW.format(zname)} ({' '.join(countries)})"[:128], zid, ext, "ALLOW",
                  "Länder-Blocking: erlaubte Länder (UniFi Controller Manager)", not wireguard)
    allow["source"]["trafficFilter"] = {"type": "REGION", "regionFilter": {"regions": countries}}
    block = _base(P_BLOCK.format(zname), zid, ext, "BLOCK",
                  "Länder-Blocking: alle anderen neuen Verbindungen (UniFi Controller Manager)")
    block.update({"connectionStateFilter": ["NEW"], "loggingEnabled": True, "enabled": enabled})
    if wireguard:
        for b in (allow, block):
            b["ipProtocolScope"] = {"ipVersion": "IPV4_AND_IPV6", "protocolFilter": {
                "type": "NAMED_PROTOCOL", "protocol": {"name": "UDP"}, "matchOpposite": False}}
            b["destination"]["trafficFilter"] = {"type": "PORT", "portFilter": {
                "type": "PORTS", "matchOpposite": False,
                "items": [{"type": "PORT_NUMBER", "value": _wg_port(data)}]}}
    out += [(P_ALLOW.format(zname), allow), (P_BLOCK.format(zname), block)]
    return out


async def _ensure_group(coordinator: UniFiCoordinator, exceptions: list[str]) -> str:
    members = sorted(set(exceptions)) or [PLACEHOLDER]
    items = list_items(members)
    group = _group(coordinator.data)
    if group is None:
        res = await coordinator.async_create_object(
            LISTS, {"type": "IPV4_ADDRESSES", "name": EXC_GROUP, "items": items}, refresh=False)
        return res["id"]
    if sorted(list_members(group)) != sorted(i["value"] for i in items):
        await coordinator.async_update_object(LISTS, group, {"items": items}, refresh=False)
    return group["_id"]


def _same(cur: dict, body: dict) -> bool:
    return all(cur.get(k) == v for k, v in body.items())


async def _sync_zone(coordinator: UniFiCoordinator, zid: str, zname: str,
                     desired: list[tuple[str, dict]]) -> None:
    data = coordinator.data
    existing = [_find(data, prefix, zid) for prefix, _ in desired]
    # Fehlt eine vordere Policy, während eine hintere existiert, stimmt die Reihenfolge
    # nach dem Anlegen nicht mehr → hintere löschen und in richtiger Reihenfolge neu anlegen.
    first_missing = next((i for i, e in enumerate(existing) if e is None), None)
    if first_missing is not None:
        for i in range(first_missing + 1, len(existing)):
            if existing[i] is not None:
                await coordinator.async_delete_object(FW, existing[i], refresh=False)
                existing[i] = None
    for (_prefix, body), cur in zip(desired, existing, strict=True):
        if cur is None:
            await coordinator.async_create_object(FW, body, refresh=False)
        elif not _same(cur, body):
            # PUT ersetzt die Policy vollständig – Felder wie Zeitplan/Flows übernehmen
            keep = {k: cur[k] for k in ("schedule", "reportFlowEnabled", "ipsecFilter")
                    if k in cur}
            await coordinator.async_update_object(FW, {**cur, **keep}, body, refresh=False)


async def _remove_zone(coordinator: UniFiCoordinator, zid: str, zname: str) -> None:
    for prefix in (P_BLOCK, P_ALLOW, P_EXC):          # Block zuerst entfernen
        cur = _find(coordinator.data, prefix.format(zname), zid)
        if cur:
            await coordinator.async_delete_object(FW, cur, refresh=False)


async def async_apply(coordinator: UniFiCoordinator, *, enabled: bool | None = None,
                      countries: list[str] | None = None, add: list[str] | None = None,
                      remove: list[str] | None = None, exceptions: list[str] | None = None,
                      zones: list[str] | None = None, wireguard: bool | None = None,
                      ) -> dict[str, Any]:
    """Soll-Zustand herstellen. Nicht angegebene Werte bleiben wie sie sind."""
    data = coordinator.data
    ext = zone_id(data, "external")
    gw = zone_id(data, "gateway")
    if not ext:
        raise UniFiApiError("Zone 'External' nicht gefunden – zonenbasierte Firewall nötig")
    cur = state(data)
    new_countries = set(cur["countries"] if countries is None else countries)
    new_countries |= set(add or [])
    new_countries -= set(remove or [])
    valid = await async_country_codes(coordinator)
    bad = sorted(c for c in new_countries if c not in valid)
    if bad:
        raise UniFiApiError(f"Vom Controller nicht unterstützte Ländercodes: {', '.join(bad)}")
    new = {
        "enabled": cur["enabled"] if enabled is None else enabled,
        "countries": sorted(new_countries),
        "zones": cur["zones"] if zones is None else zones,
        "wireguard": cur["wireguard"] if wireguard is None else wireguard,
        "exceptions": cur["exceptions"] if exceptions is None else exceptions,
    }
    if not new["countries"]:
        raise UniFiApiError("Länder-Blocking braucht mindestens ein erlaubtes Land")
    all_zones = target_zones(data)
    unknown = [z for z in new["zones"] if z not in all_zones]
    if unknown:
        raise UniFiApiError(f"Unbekannte Zonen: {', '.join(unknown)}")

    group_id = await _ensure_group(coordinator, new["exceptions"])
    for zid, zname in all_zones.items():
        if zid in new["zones"]:
            await _sync_zone(coordinator, zid, zname, _desired(
                data, zid, zname, ext, new["countries"], new["enabled"], group_id, False))
        else:
            await _remove_zone(coordinator, zid, zname)
    if gw:
        if new["wireguard"]:
            await _sync_zone(coordinator, gw, WG_NAME, _desired(
                data, gw, WG_NAME, ext, new["countries"], new["enabled"], group_id, True))
        else:
            await _remove_zone(coordinator, gw, WG_NAME)
    coordinator._force_config = True  # noqa: SLF001
    await coordinator.async_refresh()
    return state(coordinator.data)
