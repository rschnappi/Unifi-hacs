"""Länder-Blocking über Zonen-Firewall-Policies (mit Ausnahmen).

Pro Zielzone (z. B. die Zone mit der HA-Portweiterleitung) werden drei Policies gepflegt,
in genau dieser Reihenfolge (UniFi wertet pro Zonenpaar nach Index aus, neue Policies
landen hinten):

  1. Länder-Ausnahmen -> <Zone> erlauben   (Adressgruppe „HA Länder-Ausnahmen“)
  2. Länder erlauben -> <Zone>             (Quelle = erlaubte Länder)
  3. Länder-Blocking External -> <Zone> (Rest blocken)   (nur NEUE Verbindungen)

Optional dasselbe für WireGuard am Gateway (nur der WireGuard-Port, damit IPv6-RA,
DHCPv6 und IPTV vom Provider nicht getroffen werden). Das globale UniFi-„Region
Blocking“ (usg_geo) wird bewusst NICHT verwendet – es kennt keine Ausnahmen.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .api import UniFiApiError
from .countries import COUNTRIES

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator, UniFiData

EXC_GROUP = "HA Länder-Ausnahmen"
DEFAULT_EXCEPTIONS = ["160.79.104.0/21"]   # Anthropic/Claude (MCP-Connector)
PLACEHOLDER = "192.0.2.1"
INVALID_CODES = {"AN"}                     # von stat/ccode gelistet, von Policies abgelehnt
POLICIES = "v2/firewall-policies"
WG_NAME = "WireGuard"

P_EXC = "Länder-Ausnahmen -> {} erlauben"
P_ALLOW = "Länder erlauben -> {}"
P_BLOCK = "Länder-Blocking External -> {} (Rest blocken)"


# ------------------------------------------------------------------ Lesen
def _zones(data: UniFiData) -> dict[str, dict]:
    return data.config.get("firewall_zones", {}) if data else {}


def zone_id(data: UniFiData, key: str) -> str | None:
    for zid, z in _zones(data).items():
        if (z.get("zone_key") or "").lower() == key or (z.get("name") or "").lower() == key:
            return zid
    return None


def target_zones(data: UniFiData) -> dict[str, str]:
    """Auswählbare Zielzonen (ohne External/Gateway/VPN): id -> Name."""
    skip = {zone_id(data, "external"), zone_id(data, "gateway"), zone_id(data, "vpn")}
    return {zid: z.get("name", zid) for zid, z in _zones(data).items() if zid not in skip}


def _policies(data: UniFiData) -> list[dict]:
    return list(data.config.get("firewall_policies", {}).values()) if data else []


def _find(data: UniFiData, prefix: str, dest_zone: str) -> dict | None:
    for p in _policies(data):
        if (not p.get("predefined") and (p.get("name") or "").startswith(prefix)
                and (p.get("destination") or {}).get("zone_id") == dest_zone):
            return p
    return None


def _group(data: UniFiData) -> dict | None:
    for g in (data.config.get("firewall_groups", {}) if data else {}).values():
        if g.get("name") == EXC_GROUP:
            return g
    return None


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
        if allow:
            countries |= set((allow.get("source") or {}).get("regions") or [])
    wg_block = _find(data, P_BLOCK.format(WG_NAME), gw) if gw else None
    group = _group(data)
    exceptions = [m for m in (group or {}).get("group_members", []) if m != PLACEHOLDER]
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
    """Vom Controller unterstützte Ländercodes (stat/ccode), deutsche Namen wo bekannt."""
    data = await coordinator.client.request("GET", "stat/ccode") or []
    return {
        c["key"]: COUNTRIES.get(c["key"], c.get("name", c["key"]))
        for c in data if c.get("key") and c["key"] not in INVALID_CODES
    }


# ------------------------------------------------------------------ Schreiben
def _base(name: str, dest: str, src_zone: str, action: str, desc: str) -> dict[str, Any]:
    return {
        "action": action, "connection_state_type": "ALL", "connection_states": [],
        "create_allow_respond": False, "description": desc,
        "destination": {"match_opposite_ports": False, "matching_target": "ANY",
                        "port_matching_type": "ANY", "zone_id": dest},
        "enabled": True, "icmp_typename": "ANY", "icmp_v6_typename": "ANY",
        "ip_version": "BOTH", "logging": False, "match_ip_sec": False,
        "match_opposite_protocol": False, "name": name, "protocol": "all",
        "schedule": {"mode": "ALWAYS"},
        "source": {"match_opposite_ports": False, "matching_target": "ANY",
                   "port_matching_type": "ANY", "zone_id": src_zone},
    }


def _wg_port(data: UniFiData) -> str:
    for n in data.config.get("networks", {}).values():
        if n.get("vpn_type") == "wireguard-server" and n.get("local_port"):
            return str(n["local_port"])
    return "51820"


def _desired(data: UniFiData, zid: str, zname: str, ext: str, countries: list[str],
             enabled: bool, group_id: str, wireguard: bool) -> list[tuple[str, dict]]:
    """Soll-Policies in Reihenfolge (Präfix, Body)."""
    out: list[tuple[str, dict]] = []
    if not wireguard:
        exc = _base(P_EXC.format(zname), zid, ext, "ALLOW",
                    "Ausnahmen vom Länder-Blocking (UniFi Controller Manager)")
        exc["create_allow_respond"] = True
        exc["ip_version"] = "IPV4"
        exc["source"].update({"matching_target": "IP", "matching_target_type": "OBJECT",
                              "ip_group_id": group_id, "match_opposite_ips": False})
        out.append((P_EXC.format(zname), exc))
    allow = _base(f"{P_ALLOW.format(zname)} ({' '.join(countries)})"[:128], zid, ext, "ALLOW",
                  "Länder-Blocking: erlaubte Länder (UniFi Controller Manager)")
    allow["create_allow_respond"] = not wireguard
    allow["source"].update({"matching_target": "REGION", "regions": countries})
    block = _base(P_BLOCK.format(zname), zid, ext, "BLOCK",
                  "Länder-Blocking: alle anderen neuen Verbindungen (UniFi Controller Manager)")
    block.update({"connection_state_type": "CUSTOM", "connection_states": ["NEW"],
                  "logging": True, "enabled": enabled})
    if wireguard:
        for body in (allow, block):
            body["protocol"] = "udp"
            body["destination"].update({"port": _wg_port(data), "port_matching_type": "SPECIFIC"})
    out += [(P_ALLOW.format(zname), allow), (P_BLOCK.format(zname), block)]
    return out


async def _ensure_group(coordinator: UniFiCoordinator, exceptions: list[str]) -> str:
    client = coordinator.client
    members = sorted(set(exceptions)) or [PLACEHOLDER]
    group = _group(coordinator.data)
    if group is None:
        res = await client.create_object("rest/firewallgroup", {
            "name": EXC_GROUP, "group_type": "address-group", "group_members": members})
        return (res[0] if isinstance(res, list) else res)["_id"]
    if sorted(group.get("group_members", [])) != members:
        await client.update_object("rest/firewallgroup", group["_id"],
                                   {**group, "group_members": members})
    return group["_id"]


async def _sync_zone(coordinator: UniFiCoordinator, zid: str, zname: str,
                     desired: list[tuple[str, dict]]) -> None:
    client, data = coordinator.client, coordinator.data
    existing = [_find(data, prefix, zid) for prefix, _ in desired]
    # Fehlt eine vordere Policy, während eine hintere existiert, stimmt die Reihenfolge
    # nach dem Anlegen nicht mehr → hintere löschen und in richtiger Reihenfolge neu anlegen.
    first_missing = next((i for i, e in enumerate(existing) if e is None), None)
    if first_missing is not None:
        for i in range(first_missing + 1, len(existing)):
            if existing[i] is not None:
                await client.delete_object(POLICIES, existing[i]["_id"])
                existing[i] = None
    for (_prefix, body), cur in zip(desired, existing, strict=True):
        if cur is None:
            await client.create_object(POLICIES, body)
        else:
            keep = {k: v for k, v in cur.items() if k not in ("hits", "last_hit")}
            await client.update_object(POLICIES, cur["_id"], {**keep, **body, "_id": cur["_id"]})


async def _remove_zone(coordinator: UniFiCoordinator, zid: str, zname: str) -> None:
    for prefix in (P_BLOCK, P_ALLOW, P_EXC):          # Block zuerst entfernen
        cur = _find(coordinator.data, prefix.format(zname), zid)
        if cur:
            await coordinator.client.delete_object(POLICIES, cur["_id"])


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
