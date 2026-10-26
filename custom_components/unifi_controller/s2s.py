"""Site-to-Site-Tunnel zu einer Firmen-Firewall (z. B. Sophos XGS mit XFRM) – Generator.

A) richtet die UniFi-Seite ein (idempotent, verändert nie Vorhandenes):
   Adressliste der Firmennetze, Zone, eigenes Netz (VLAN, Subnetz, Firmen-DNS), RADIUS-Profil,
   routenbasierter IPsec-Tunnel (IKEv2/VTI, deaktiviert), Policy-Based Routes mit Kill-Switch,
   Firewall-Policies (strikte Trennung vom Heimnetz) und WLAN mit Firmen-RADIUS (deaktiviert).
B) erzeugt die Anleitung für die Gegenstelle (Markdown + druckbares HTML) mit allen Werten.

Bekannte Stolpersteine (S1–S11) werden geprüft und als Hinweis gemeldet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import html
import ipaddress
import logging
import os
import random
import secrets
import socket
import string
from typing import TYPE_CHECKING, Any

from homeassistant.util import dt as dt_util

from .api import UniFiApiError
from .const import CONF_BAN_GROUP, DEFAULT_BAN_GROUP, DOMAIN
from .region import legacy_zone_id, zone_id, zone_of_network

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

SUBENTRY_S2S = "site_to_site"
POLICIES = "sites/{site}/firewall/policies"
ZONES = "sites/{site}/firewall/zones"
LISTS = "sites/{site}/traffic-matching-lists"
DOC_DIR = "unifi_controller/site_to_site"

DEFAULTS: dict[str, Any] = {
    "firma": "Firma", "peer_fqdn": "", "local_id": "", "remote_nets": [], "remote_dns": [],
    "radius_servers": [], "ssid": None, "full_tunnel": True, "allow_support": True,
    "preferred_vlan": 50, "preferred_subnet": "172.20.50.0/24", "subnet_pool": "172.20.0.0/14",
    "transfer_pool": "10.255.0.0/16",
    # Objektnamen – leer = aus „firma“ abgeleitet (für bereits vorhandene Objekte überschreiben)
    "group_name": "", "zone_name": "", "net_name": "", "radius_name": "", "tunnel_name": "",
}
NAME_KEYS = ("group_name", "zone_name", "net_name", "radius_name", "tunnel_name")


class S2SError(UniFiApiError):
    """Abbruch vor/bei der Einrichtung (nichts weiter verändert)."""


# ---------------------------------------------------------------------- Konfiguration
@dataclass
class S2SConfig:
    firma: str
    peer_fqdn: str
    local_id: str
    remote_nets: list[str]
    remote_dns: list[str]
    radius_servers: list[str]
    ssid: str | None
    full_tunnel: bool
    allow_support: bool
    preferred_vlan: int
    preferred_subnet: str
    subnet_pool: str
    transfer_pool: str
    group_name: str = ""
    zone_name: str = ""
    net_name: str = ""
    radius_name: str = ""
    tunnel_name: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> S2SConfig:
        v = DEFAULTS | {k: val for k, val in d.items() if k in DEFAULTS and val not in (None, "")}
        if "ssid" in d:
            v["ssid"] = d.get("ssid") or None
        elif d.get("radius_servers"):
            v["ssid"] = v["firma"]
        return cls(**{k: v[k] for k in DEFAULTS})

    # Objektnamen (Präfix = Firma, einzeln überschreibbar)
    @property
    def group(self) -> str:
        return self.group_name or f"{self.firma} Netze"

    @property
    def zone(self) -> str:
        return self.zone_name or self.firma

    @property
    def net(self) -> str:
        return self.net_name or self.firma

    @property
    def radius(self) -> str:
        return self.radius_name or f"{self.firma} RADIUS"

    @property
    def tunnel(self) -> str:
        return self.tunnel_name or f"{self.firma} Site-to-Site"


def split_list(value: Any) -> list[str]:
    """Kommas, Leerzeichen oder Zeilen → Liste."""
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").replace(";", ",").replace("\n", ",").replace(" ", ",").split(",")
    return [i.strip() for i in items if i and i.strip()]


def validate_input(d: dict[str, Any]) -> dict[str, str]:
    """Formularprüfung → {feld: fehlerschlüssel}."""
    errors: dict[str, str] = {}
    firma = str(d.get("firma") or "").strip()
    if not firma or len(firma) > 24 or not all(c.isalnum() or c in " ._-" for c in firma):
        errors["firma"] = "invalid_firma"
    if not d.get("peer_fqdn") or "." not in str(d["peer_fqdn"]):
        errors["peer_fqdn"] = "invalid_fqdn"
    if not d.get("local_id") or "." not in str(d["local_id"]):
        errors["local_id"] = "invalid_fqdn"
    nets = split_list(d.get("remote_nets"))
    try:
        if not nets:
            raise ValueError
        for n in nets:
            ipaddress.ip_network(n, strict=False)
    except ValueError:
        errors["remote_nets"] = "invalid_nets"
    dns = split_list(d.get("remote_dns"))
    try:
        if not dns or len(dns) > 2:
            raise ValueError
        for ip in dns:
            ipaddress.IPv4Address(ip)
    except ValueError:
        errors["remote_dns"] = "invalid_dns"
    try:
        for ip in split_list(d.get("radius_servers")):
            ipaddress.IPv4Address(ip)
    except ValueError:
        errors["radius_servers"] = "invalid_ips"
    if d.get("ssid") and not split_list(d.get("radius_servers")):
        errors["ssid"] = "ssid_needs_radius"
    for key in ("preferred_subnet", "subnet_pool", "transfer_pool"):
        if key in d:
            try:
                ipaddress.ip_network(str(d[key]), strict=True)
            except ValueError:
                errors[key] = "invalid_net"
    if "preferred_subnet" in d and not errors.get("preferred_subnet") and \
            ipaddress.ip_network(str(d["preferred_subnet"])).prefixlen != 24:
        errors["preferred_subnet"] = "need_24"
    return errors


def normalize(d: dict[str, Any]) -> dict[str, Any]:
    out = dict(d)
    for key in ("remote_nets", "remote_dns", "radius_servers"):
        if key in out:
            out[key] = split_list(out[key])
    if "remote_nets" in out:
        out["remote_nets"] = [str(ipaddress.ip_network(n, strict=False)) for n in out["remote_nets"]]
    for key in ("firma", "peer_fqdn", "local_id", "ssid"):
        if isinstance(out.get(key), str):
            out[key] = out[key].strip()
    return out


# ---------------------------------------------------------------------- Bericht
@dataclass
class Report:
    apply: bool
    steps: list[tuple[str, str]] = field(default_factory=list)   # (ok|neu|plan|warn|info, Text)
    warnings: list[str] = field(default_factory=list)
    secrets: dict[str, str] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)

    def ok(self, t: str) -> None:
        self.steps.append(("ok", t))

    def new(self, t: str) -> None:
        self.steps.append(("neu" if self.apply else "plan", t))

    def info(self, t: str) -> None:
        self.steps.append(("info", t))

    def ren(self, t: str) -> None:
        self.steps.append(("ren" if self.apply else "plan_ren", t))

    def warn(self, t: str) -> None:
        self.steps.append(("warn", t))
        self.warnings.append(t)

    def markdown(self) -> str:
        icon = {"ok": "✅", "neu": "🆕", "plan": "➕", "warn": "⚠️", "info": "ℹ️",
                "ren": "✏️", "plan_ren": "✏️"}
        return "\n".join(f"{icon[s]} {t}" for s, t in self.steps)

    @property
    def created(self) -> list[str]:
        return [t for s, t in self.steps if s in ("neu", "plan")]

    @property
    def renamed(self) -> list[str]:
        return [t for s, t in self.steps if s in ("ren", "plan_ren")]


# ---------------------------------------------------------------------- Hilfen
def _pw(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _net(cidr: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_interface(cidr).network


def _overlaps(a: str, others: list[str]) -> list[str]:
    na = _net(a)
    return [o for o in others if na.overlaps(_net(o))]


def _free_subnet(preferred: str, pool: str, used: list[str]) -> str | None:
    pref = ipaddress.ip_network(preferred)
    if not _overlaps(str(pref), used):
        return str(pref)
    for cand in ipaddress.ip_network(pool).subnets(new_prefix=24):
        if not _overlaps(str(cand), used):
            return str(cand)
    return None


def _random_subnet(pool: str, prefix: int, used: list[str]) -> str | None:
    cands = list(ipaddress.ip_network(pool).subnets(new_prefix=prefix))
    random.SystemRandom().shuffle(cands)
    for cand in cands[:5000]:
        if not _overlaps(str(cand), used):
            return str(cand)
    return None


async def _resolve(hass, fqdn: str) -> str | None:
    try:
        infos = await hass.loop.getaddrinfo(fqdn, None, family=socket.AF_INET)
    except OSError:
        return None
    return infos[0][4][0] if infos else None


def _side(zone: str, ips: list[str] | None = None, tml: str | None = None,
          opposite: bool = False, ports: tuple[int, int] | None = None) -> dict:
    side: dict[str, Any] = {"zoneId": zone}
    tf: dict[str, Any] = {}
    if tml:
        tf = {"type": "IP_ADDRESS", "ipAddressFilter": {
            "type": "TRAFFIC_MATCHING_LIST", "matchOpposite": False,
            "trafficMatchingListId": tml}}
    elif ips:
        tf = {"type": "IP_ADDRESS", "ipAddressFilter": {
            "type": "IP_ADDRESSES", "matchOpposite": opposite,
            "items": [{"type": "SUBNET" if "/" in i else "IP_ADDRESS", "value": i} for i in ips]}}
    if ports:
        port = {"type": "PORTS", "matchOpposite": False,
                "items": [{"type": "PORT_NUMBER_RANGE", "start": ports[0], "stop": ports[1]}]}
        if tf:
            tf["portFilter"] = port
        else:
            tf = {"type": "PORT", "portFilter": port}
    if tf:
        side["trafficFilter"] = tf
    return side


def _policy(name: str, desc: str, action: str, src: dict, dst: dict, *,
            proto: str | None = None, states: list[str] | None = None, log: bool = False,
            respond: bool = False) -> dict:
    body: dict[str, Any] = {
        "enabled": True, "name": name[:128], "description": desc[:256],
        "action": {"type": action, **({"allowReturnTraffic": respond} if action == "ALLOW" else {})},
        "source": src, "destination": dst,
        "ipProtocolScope": {"ipVersion": "IPV4"}, "loggingEnabled": log,
    }
    if proto:
        body["ipProtocolScope"]["protocolFilter"] = {
            "type": "NAMED_PROTOCOL", "protocol": {"name": proto}, "matchOpposite": False}
    if states:
        body["connectionStateFilter"] = states
    return body


def _same_policy(p: dict, d: dict) -> bool:
    """Gleiche Quell-/Zielzone, Aktion (und Protokoll, falls eingeschränkt) = vorhanden."""
    if (p.get("metadata") or {}).get("origin") not in (None, "USER_DEFINED"):
        return False
    if (p.get("action") or {}).get("type") != d["action"]["type"]:
        return False
    if (p.get("source") or {}).get("zoneId") != d["source"]["zoneId"] or \
            (p.get("destination") or {}).get("zoneId") != d["destination"]["zoneId"]:
        return False
    want = ((d.get("ipProtocolScope") or {}).get("protocolFilter") or {}).get("protocol")
    have = ((p.get("ipProtocolScope") or {}).get("protocolFilter") or {}).get("protocol")
    return not want or want == have


# ---------------------------------------------------------------------- Ablauf
async def async_run(coordinator: UniFiCoordinator, cfg: S2SConfig, apply: bool,
                    backup: bool = True, rename: bool = False) -> Report:
    """apply=False → nur prüfen und planen (Dry-Run).

    rename=True → vorhandene, am Inhalt erkannte Objekte bekommen die neuen Namen
    (das Einzige, was an Vorhandenem geändert wird).
    """
    r = Report(apply=apply)
    hass = coordinator.hass
    client = coordinator.client

    # ---------------------------------------------------------------- 0. Vorprüfungen
    coordinator._force_config = True  # noqa: SLF001 – frische Konfiguration
    await coordinator.async_refresh()
    data = coordinator.data
    if data is None:
        raise S2SError("Keine Daten vom Controller")
    r.ok(f"Controller erreichbar – Network {data.sysinfo.get('version', '?')}")

    peer_ip = await _resolve(hass, cfg.peer_fqdn)
    if not peer_ip:
        raise S2SError(f"{cfg.peer_fqdn} ist nicht auflösbar [S11]")
    r.ok(f"{cfg.peer_fqdn} → {peer_ip}")

    nets: dict[str, dict] = data.config.get("networks", {})
    zones: dict[str, dict] = data.config.get("firewall_zones", {})
    lists: dict[str, dict] = data.config.get("firewall_groups", {})
    pols = list(data.config.get("firewall_policies", {}).values())
    routes = list(data.config.get("trafficroutes", {}).values())
    wlans = list(data.config.get("wlans", {}).values())
    try:
        radius = await client.request("GET", "rest/radiusprofile") or []
    except UniFiApiError as err:
        raise S2SError(f"RADIUS-Profile nicht lesbar: {err} [S1]") from err

    z_ext, z_vpn, z_gw = (zone_id(data, k) for k in ("external", "vpn", "gateway"))
    if not (z_ext and z_vpn and z_gw):
        raise S2SError("Zonenbasierte Firewall (External/VPN/Gateway) nicht gefunden")
    zone_names = {zid: z.get("name", zid) for zid, z in zones.items()}

    local = [_net(n["ip_subnet"]).with_prefixlen for n in nets.values()
             if n.get("ip_subnet") and n.get("purpose") != "wan" and n.get("name") != cfg.net]
    for rn in cfg.remote_nets:
        if hit := _overlaps(rn, local):
            raise S2SError(f"Firmennetz {rn} überlappt lokales Netz {', '.join(hit)} [S2]")
    r.ok("Keine Überlappung zwischen Firmennetzen und lokalen Netzen")
    wg = [_net(n["ip_subnet"]).with_prefixlen for n in nets.values()
          if n.get("purpose") == "remote-user-vpn" and n.get("ip_subnet")]
    if wg:
        r.info(f"Client-VPN-Netze in der VPN-Zone: {', '.join(wg)} – von Sperren ausgenommen")

    aps = [d for d in data.devices.values() if d.get("type") == "uap" and d.get("ip")]
    mgmt = mgmt_zone = None
    ap_ips = [d["ip"] for d in aps]
    if cfg.radius_servers:
        if not aps:
            raise S2SError("Keine Access Points gefunden (für RADIUS nötig)")
        ip0 = ipaddress.ip_address(ap_ips[0])
        mgmt = next((n for n in nets.values() if n.get("ip_subnet")
                     and ip0 in _net(n["ip_subnet"]) and n.get("purpose") != "wan"), None)
        if mgmt is None:
            raise S2SError("Verwaltungsnetz der Access Points nicht gefunden")
        mgmt_zone = zone_of_network(data, mgmt)
        r.ok("Access Points: " + ", ".join(f"{d.get('name')} {d['ip']}" for d in aps)
             + f" – Verwaltungsnetz {mgmt.get('name')} (Zone {zone_names.get(mgmt_zone, '?')})")
        for d in aps:
            if (d.get("config_network") or {}).get("type") != "static":
                r.warn(f"AP {d.get('name')} ({d['ip']}) hat eine DHCP-Adresse – ändert sie sich, "
                       "stimmen RADIUS-Route/-Regel und NPS-Client nicht mehr. Feste IP empfohlen [S7]")

    ban = coordinator.config_entry.options.get(CONF_BAN_GROUP, DEFAULT_BAN_GROUP)
    for tml in lists.values():
        if tml.get("name") == ban and any(i.get("value") == peer_ip for i in tml.get("items", [])):
            r.warn(f"Die Gegenstelle {peer_ip} steht in der Fail2Ban-Liste „{ban}“ [S10]")

    # ---------------------------------------------------------------- Backup
    if apply and backup:
        from .button import async_create_backup  # noqa: PLC0415

        try:
            res = await async_create_backup(coordinator)
        except UniFiApiError as err:
            raise S2SError(f"Backup fehlgeschlagen ({err}) – es wurde nichts verändert") from err
        r.ok(f"Backup gespeichert: {res['path']} ({res['size_kb']} KB)")
    elif apply:
        r.warn("Ohne Backup ausgeführt")

    async def create(label: str, coro_factory) -> Any:
        r.new(label)
        if not apply:
            return None
        try:
            return await coro_factory()
        except UniFiApiError as err:
            raise S2SError(f"{label}: {err}") from err

    async def same_or_rename(what: str, old: str, new: str, coro_factory) -> None:
        """Vorhandenes Objekt: Name gleich → ok, sonst umbenennen (Option) oder Hinweis."""
        if (old or "") == new:
            r.ok(f"{what} „{new}“ vorhanden – unverändert")
            return
        if not rename:
            r.ok(f"{what} „{old}“ vorhanden (gleicher Inhalt) – unverändert; "
                 f"Umbenennen in „{new}“ möglich")
            return
        r.ren(f"{what} „{old}“ → „{new}“")
        if apply:
            try:
                await coro_factory()
            except UniFiApiError as err:
                r.warn(f"{what} „{old}“ nicht umbenannt: {err}")

    # ---------------------------------------------------------------- 1. Adressliste
    want_items = set(cfg.remote_nets)
    grp = next((t for t in lists.values() if t.get("name") == cfg.group), None) or next(
        (t for t in lists.values() if t.get("type") == "IPV4_ADDRESSES"
         and {i.get("value") for i in t.get("items", [])} == want_items), None)
    if grp:
        have = {i.get("value") for i in grp.get("items", [])}
        await same_or_rename("Adressliste", grp.get("name"), cfg.group,
                             lambda: coordinator.async_update_object(
                                 "firewall_groups", grp, {"name": cfg.group}, refresh=False))
        if miss := [n for n in cfg.remote_nets if n not in have]:
            r.warn(f"In „{cfg.group}“ fehlen: {', '.join(miss)} – bei Bedarf ergänzen")
        grp_id = grp["id"]
    else:
        res = await create(f"Adressliste „{cfg.group}“: {', '.join(cfg.remote_nets)}",
                           lambda: client.integration("POST", LISTS, {
                               "type": "IPV4_ADDRESSES", "name": cfg.group,
                               "items": [{"type": "SUBNET", "value": n} for n in cfg.remote_nets]}))
        grp_id = (res or {}).get("id", "<neu>")

    # ---------------------------------------------------------------- 2. Zone
    z_firma = zone_id(data, cfg.zone.lower())
    if z_firma:
        r.ok(f"Zone „{cfg.zone}“ vorhanden – unverändert")
    else:
        res = await create(f"Zone „{cfg.zone}“", lambda: client.integration(
            "POST", ZONES, {"name": cfg.zone, "networkIds": []}))
        z_firma = (res or {}).get("id", "<neu>")
        if apply:
            coordinator._force_config = True  # noqa: SLF001
            await coordinator.async_refresh()   # interne Zonen-ID für das Netz
            data = coordinator.data
    zone_names[z_firma] = cfg.zone

    # ---------------------------------------------------------------- 3. Netz
    net = next((n for n in nets.values()
                if n.get("name") == cfg.net and n.get("purpose") == "corporate"), None)
    if net:
        firma_cidr = _net(net["ip_subnet"]).with_prefixlen
        r.ok(f"Netz „{cfg.net}“ vorhanden ({firma_cidr}, VLAN {net.get('vlan')}) – unverändert")
        if zone_of_network(data, net) != z_firma:
            r.warn(f"Netz „{cfg.net}“ liegt nicht in Zone „{cfg.zone}“")
        if not net.get("dhcpd_dns_enabled") or net.get("dhcpd_dns_1") not in cfg.remote_dns:
            r.warn(f"Netz „{cfg.net}“ verteilt nicht die Firmen-DNS-Server per DHCP")
        net_id = net["_id"]
    else:
        used_vlans = {int(n["vlan"]) for n in nets.values() if str(n.get("vlan") or "").isdigit()}
        vlan = cfg.preferred_vlan
        while vlan in used_vlans:
            vlan += 1
        firma_cidr = _free_subnet(cfg.preferred_subnet, cfg.subnet_pool,
                                  local + cfg.remote_nets + [cfg.transfer_pool])
        if not firma_cidr:
            raise S2SError(f"Kein freies /24 in {cfg.subnet_pool}")
        hosts = list(ipaddress.ip_network(firma_cidr).hosts())
        legacy_zone = legacy_zone_id(data, z_firma) if apply else "<neu>"
        if apply and not legacy_zone:
            raise S2SError(f"Interne ID der Zone „{cfg.zone}“ nicht gefunden")
        body = {
            "name": cfg.net, "purpose": "corporate", "networkgroup": "LAN", "enabled": True,
            "vlan_enabled": True, "vlan": vlan, "ip_subnet": f"{hosts[0]}/24",
            "dhcpd_enabled": True, "dhcpd_start": str(hosts[19]), "dhcpd_stop": str(hosts[249]),
            "dhcpd_dns_enabled": True, "dhcpd_dns_1": cfg.remote_dns[0],
            "dhcpd_dns_2": cfg.remote_dns[1] if len(cfg.remote_dns) > 1 else "",
            "firewall_zone_id": legacy_zone, "internet_access_enabled": True,
            "mdns_enabled": False, "network_isolation_enabled": False,
            "setting_preference": "manual", "ipv6_setting_preference": "manual",
        }
        res = await create(f"Netz „{cfg.net}“ {firma_cidr}, VLAN {vlan}, DNS "
                           f"{' / '.join(cfg.remote_dns)}",
                           lambda: client.create_object("rest/networkconf", body))
        created = (res[0] if isinstance(res, list) and res else res) or {}
        net_id = created.get("_id", "<neu>")

    # ---------------------------------------------------------------- 4. RADIUS
    rad_id = None
    rad_secret = None
    if cfg.radius_servers:
        rad = next((p for p in radius if p.get("name") == cfg.radius), None) or next(
            (p for p in radius if {s.get("ip") for s in p.get("auth_servers", [])}
             == set(cfg.radius_servers)), None)
        if rad:
            await same_or_rename(
                "RADIUS-Profil", rad.get("name"), cfg.radius,
                lambda: client.update_object("rest/radiusprofile", rad["_id"],
                                             {**rad, "name": cfg.radius}))
            have = {s.get("ip") for s in rad.get("auth_servers", [])}
            if miss := [ip for ip in cfg.radius_servers if ip not in have]:
                r.warn(f"RADIUS-Profil: Server fehlen: {', '.join(miss)}")
            rad_secret = next((s.get("x_secret") for s in rad.get("auth_servers", [])
                               if s.get("x_secret")), None)
            rad_id = rad["_id"]
        else:
            rad_secret = _pw(40)
            r.secrets["RADIUS Shared Secret"] = rad_secret

            def srv(port: int) -> list[dict]:
                return [{"ip": ip, "port": port, "x_secret": rad_secret}
                        for ip in cfg.radius_servers]
            res = await create(f"RADIUS-Profil „{cfg.radius}“ ({', '.join(cfg.radius_servers)})",
                               lambda: client.create_object("rest/radiusprofile", {
                                   "name": cfg.radius, "auth_servers": srv(1812),
                                   "acct_servers": srv(1813), "accounting_enabled": True,
                                   "interim_update_enabled": True,
                                   "interim_update_interval": 3600,
                                   "use_usg_auth_server": False, "use_usg_acct_server": False,
                                   "vlan_enabled": False}))
            created = (res[0] if isinstance(res, list) and res else res) or {}
            rad_id = created.get("_id", "<neu>")

    # ---------------------------------------------------------------- 5. Tunnel
    # am Namen oder an der Gegenstelle erkennen – UniFi erlaubt je Peer-IP nur einen Tunnel
    tun = next((n for n in nets.values()
                if n.get("name") == cfg.tunnel and n.get("purpose") == "site-vpn"), None) or next(
        (n for n in nets.values()
         if n.get("purpose") == "site-vpn" and n.get("ipsec_peer_ip") == peer_ip), None)
    if tun:
        transfer = tun.get("ipsec_tunnel_ip") or ""
        psk = tun.get("x_ipsec_pre_shared_key")
        r.info(f"Tunnel: Peer {tun.get('ipsec_peer_ip')}, VTI {transfer}, "
               f"aktiv: {tun.get('enabled')}")
        await same_or_rename("Tunnel", tun.get("name"), cfg.tunnel,
                             lambda: coordinator.async_update_object(
                                 "networks", tun, {"name": cfg.tunnel}, refresh=False))
        if tun.get("ipsec_peer_ip") != peer_ip:
            r.warn(f"Tunnel-Peer {tun.get('ipsec_peer_ip')} ≠ aktuelle Auflösung von "
                   f"{cfg.peer_fqdn} ({peer_ip})")
        if tun.get("ipsec_key_exchange") not in (None, "ikev2"):
            r.warn("Tunnel: IKE-Version nicht IKEv2 – in der UI prüfen [S5]")
        tun_id = tun["_id"]
    else:
        used_t = local + cfg.remote_nets + [firma_cidr] + wg + [
            _net(n["ipsec_tunnel_ip"]).with_prefixlen for n in nets.values()
            if n.get("ipsec_tunnel_ip")]
        t_net = _random_subnet(cfg.transfer_pool, 30, used_t)
        if not t_net:
            raise S2SError(f"Kein freies /30-Transfernetz in {cfg.transfer_pool}")
        t_hosts = list(ipaddress.ip_network(t_net).hosts())
        transfer = f"{t_hosts[1]}/30"
        psk = _pw(48)
        r.secrets["IPsec Pre-Shared Key"] = psk
        body = {
            "name": cfg.tunnel, "purpose": "site-vpn", "vpn_type": "ipsec-vpn", "enabled": False,
            "ipsec_peer_ip": peer_ip, "ipsec_interface": "wan", "ipsec_key_exchange": "ikev2",
            "ipsec_profile": "customized",
            "ipsec_ike_encryption": "aes256", "ipsec_ike_hash": "sha256",
            "ipsec_ike_dh_group": 19, "ipsec_ike_lifetime": "28800",
            "ipsec_esp_encryption": "aes256", "ipsec_esp_hash": "sha256",
            "ipsec_esp_dh_group": 19, "ipsec_esp_lifetime": "3600",
            "ipsec_encryption": "aes256", "ipsec_hash": "sha256", "ipsec_dh_group": 19,
            "ipsec_pfs": True,
            "ipsec_local_identifier_enabled": True, "ipsec_local_identifier": cfg.local_id,
            "ipsec_remote_identifier_enabled": True, "ipsec_remote_identifier": cfg.peer_fqdn,
            "ipsec_tunnel_ip_enabled": True, "ipsec_tunnel_ip": transfer,
            "ipsec_dynamic_routing": True, "route_distance": 30, "remote_vpn_subnets": [],
            "ipsec_separate_ikev2_networks": False, "x_ipsec_pre_shared_key": psk,
        }
        res = await create(f"Tunnel „{cfg.tunnel}“ → {peer_ip}, VTI {transfer} (deaktiviert)",
                           lambda: client.create_object("rest/networkconf", body))
        created = (res[0] if isinstance(res, list) and res else res) or {}
        tun_id = created.get("_id", "<neu>")
        r.info("IKE-Version wird über die API teils nicht übernommen – vor dem Aktivieren in "
               "der UI „IKEv2“ prüfen [S5]")
    t_net = _net(transfer) if transfer else None
    sophos_xfrm = f"{list(t_net.hosts())[0]}/30" if t_net else "?"

    # ---------------------------------------------------------------- 6. Routen
    def ip_list(items: list[str]) -> list[dict]:
        return [{"ip_or_subnet": i, "ip_version": "v4", "port_ranges": [], "ports": []}
                for i in items]
    route_defs = [(f"{cfg.firma} → {cfg.firma} Netze über Tunnel", "IP",
                   ip_list(cfg.remote_nets), net_id)]
    if cfg.full_tunnel:
        route_defs.append((f"{cfg.firma} → Internet nur über Tunnel (Full Tunnel)",
                           "INTERNET", [], net_id))
    if cfg.radius_servers and mgmt:
        route_defs.append((f"Access Points → {cfg.firma} RADIUS über Tunnel", "IP",
                           ip_list(cfg.radius_servers), mgmt["_id"]))
    for desc, target, ips, src in route_defs:
        ex = next((x for x in routes if x.get("network_id") == tun_id
                   and x.get("matching_target") == target
                   and src in [t.get("network_id") for t in x.get("target_devices", [])]), None)
        if ex:
            await same_or_rename("Route", ex.get("description"), desc,
                                 lambda ex=ex, desc=desc: client.request(
                                     "PUT", f"v2/trafficroutes/{ex['_id']}",
                                     {**ex, "description": desc}))
            if target == "IP":
                have = {i.get("ip_or_subnet") for i in ex.get("ip_addresses", [])}
                if miss := [i["ip_or_subnet"] for i in ips if i["ip_or_subnet"] not in have]:
                    r.warn(f"Route „{ex.get('description')}“: Ziele fehlen: {', '.join(miss)}")
            continue
        await create(f"Route „{desc}“ (Kill-Switch)", lambda desc=desc, target=target, ips=ips,
                     src=src: client.request("POST", "v2/trafficroutes", {
                         "description": desc, "enabled": True, "matching_target": target,
                         "ip_addresses": ips, "ip_ranges": [], "domains": [], "regions": [],
                         "network_id": tun_id, "next_hop": "", "kill_switch_enabled": True,
                         "target_devices": [{"network_id": src, "type": "NETWORK"}]}))

    # ---------------------------------------------------------------- 7. Firewall
    f = cfg.firma
    defs: list[dict] = [_policy(
        f"{f} -> Tunnel erlauben",
        f"Netz {cfg.net} darf in den Tunnel ({f}-Netze{' + Internet' if cfg.full_tunnel else ''})",
        "ALLOW", _side(z_firma), _side(z_vpn), respond=True)]
    if cfg.full_tunnel:
        defs.append(_policy(f"{f} -> Internet lokal blocken",
                            f"Full Tunnel: Netz {cfg.net} nur über die Gegenstelle ins Internet",
                            "BLOCK", _side(z_firma), _side(z_ext), log=True))
    if cfg.radius_servers and mgmt_zone:
        defs.append(_policy(f"Access Points -> {f} RADIUS erlauben",
                            "Einzige Ausnahme vom Heimnetz in den Tunnel: RADIUS der Access Points",
                            "ALLOW", _side(mgmt_zone, ap_ips),
                            _side(z_vpn, cfg.radius_servers, ports=(1812, 1813)),
                            proto="UDP", respond=True))
    if mgmt_zone:
        defs.append(_policy(f"Infra -> {f} Netze blocken",
                            f"Verwaltungsnetz hat keinen Zugang zu den {f}-Netzen – außer RADIUS",
                            "BLOCK", _side(mgmt_zone), _side(z_vpn, tml=grp_id), log=True))
    if cfg.allow_support:
        defs.append(_policy(f"{f} Netze -> {cfg.net} erlauben",
                            f"{f}-Netze dürfen ins Netz {cfg.net} (Support, Softwareverteilung)",
                            "ALLOW", _side(z_vpn, tml=grp_id), _side(z_firma), respond=True))
    for zid, zname in sorted(zone_names.items(), key=lambda i: i[1]):
        if zid in (z_firma, z_vpn, z_ext):
            continue
        defs.append(_policy(f"{f} Tunnel -> {zname} blocken",
                            f"Der {f}-Tunnel darf keine Verbindungen in „{zname}“ aufbauen – "
                            "Client-VPN ausgenommen", "BLOCK",
                            _side(z_vpn, wg, opposite=True) if wg else _side(z_vpn),
                            _side(zid), states=["NEW", "INVALID"], log=True))
    for d in defs:
        if ex := next((p for p in pols if _same_policy(p, d)), None):
            await same_or_rename("Regel", ex.get("name"), d["name"],
                                 lambda ex=ex, d=d: coordinator.async_update_object(
                                     "firewall_policies", ex,
                                     {"name": d["name"], "description": d["description"]},
                                     refresh=False))
            continue
        await create(f"Regel „{d['name']}“", lambda d=d: client.integration("POST", POLICIES, d))

    # ---------------------------------------------------------------- 8. WLAN
    if cfg.ssid:
        wl = next((w for w in wlans if w.get("name") == cfg.ssid), None)
        if wl:
            r.ok(f"WLAN „{cfg.ssid}“ vorhanden (aktiv: {wl.get('enabled')}) – unverändert")
        elif len([w for w in wlans if w.get("ap_group_mode") in (None, "all")]) >= 4:
            r.warn(f"Bereits {len(wlans)} WLANs (auch deaktivierte zählen) – APs erlauben max. 4 "
                   f"je Funkband. WLAN „{cfg.ssid}“ wird NICHT angelegt: ein ungenutztes löschen "
                   "oder umwidmen und erneut ausführen [S3]")
        else:
            tpl = wlans[0] if wlans else {}
            await create(f"WLAN „{cfg.ssid}“ (WPA2/3-Enterprise, deaktiviert)",
                         lambda: client.create_object("rest/wlanconf", {
                             "name": cfg.ssid, "enabled": False, "security": "wpaeap",
                             "wpa_mode": "wpa2", "wpa_enc": "ccmp", "wpa3_support": True,
                             "wpa3_transition": True, "pmf_mode": "optional",
                             "radiusprofile_id": rad_id, "networkconf_id": net_id,
                             "vlan_enabled": False, "ap_group_ids": tpl.get("ap_group_ids", []),
                             "ap_group_mode": "all", "usergroup_id": tpl.get("usergroup_id"),
                             "wlan_band": "both", "wlan_bands": ["2g", "5g"],
                             "bss_transition": True, "is_guest": False, "hide_ssid": False,
                             "l2_isolation": False, "nas_identifier_type": "bssid",
                             "setting_preference": "manual"}))

    # ---------------------------------------------------------------- 9. Nachprüfung
    if apply:
        coordinator._force_config = True  # noqa: SLF001
        await coordinator.async_refresh()
        data = coordinator.data
        if cfg.ssid:
            wl = next((w for w in data.config.get("wlans", {}).values()
                       if w.get("name") == cfg.ssid), None)
            if wl and wl.get("networkconf_id") != net_id:
                r.warn(f"WLAN „{cfg.ssid}“ hängt nicht am Netz „{cfg.net}“ (API übernimmt das "
                       f"teils nicht) – in der UI: WiFi → {cfg.ssid} → Netzwerk = {cfg.net} [S4]")
        if cfg.radius_servers and mgmt_zone:
            await _fix_order(coordinator, r, mgmt_zone, z_vpn)
        for p in data.config.get("firewall_policies", {}).values():
            if ((p.get("metadata") or {}).get("origin") == "USER_DEFINED"
                    and (p.get("action") or {}).get("type") == "ALLOW"
                    and (p.get("source") or {}).get("zoneId") == z_vpn
                    and (p.get("destination") or {}).get("zoneId") not in (z_firma, z_ext, z_vpn)
                    and not (p.get("source") or {}).get("trafficFilter")):
                r.warn(f"Regel „{p.get('name')}“ (VPN → "
                       f"{zone_names.get(p['destination']['zoneId'], '?')}) hat keine "
                       "Quellbeschränkung und gilt damit auch für den Firmentunnel [S6]")

    r.values = {
        "firma": f, "peer_fqdn": cfg.peer_fqdn, "peer_ip": peer_ip, "local_id": cfg.local_id,
        "psk": psk, "radius_secret": rad_secret, "transfer": transfer,
        "sophos_xfrm": sophos_xfrm, "transfer_net": t_net.with_prefixlen if t_net else "?",
        "net_name": cfg.net, "firma_cidr": firma_cidr, "ap_ips": ap_ips,
        "aps": [(d.get("name") or d.get("mac"), d["ip"]) for d in aps],
        "remote_nets": cfg.remote_nets, "radius_servers": cfg.radius_servers,
        "remote_dns": cfg.remote_dns, "ssid": cfg.ssid, "tunnel": cfg.tunnel,
        "radius_name": cfg.radius, "full_tunnel": cfg.full_tunnel,
        "allow_support": cfg.allow_support, "controller": coordinator.client.host,
        "dry_run": not apply,
    }
    return r


async def _fix_order(coordinator: UniFiCoordinator, r: Report, src: str, dst: str) -> None:
    """RADIUS-Erlauben muss vor „Infra → Firmennetze blocken“ stehen [S9]."""
    client = coordinator.client
    path = (f"{POLICIES}/ordering?sourceFirewallZoneId={src}&destinationFirewallZoneId={dst}")
    try:
        res = await client.integration("GET", path)
        ids = (res.get("orderedFirewallPolicyIds") or {}).get("beforeSystemDefined") or []
        pols = coordinator.data.config.get("firewall_policies", {})

        def kind(pid: str) -> str:
            return ((pols.get(pid) or {}).get("action") or {}).get("type", "")
        allow = next((i for i in ids if kind(i) == "ALLOW"), None)
        block = next((i for i in ids if kind(i) == "BLOCK"), None)
        if not allow or not block or ids.index(allow) < ids.index(block):
            r.ok("Reihenfolge stimmt: RADIUS erlauben vor Verwaltungsnetz blocken")
            return
        ids.remove(allow)
        ids.insert(ids.index(block), allow)
        await client.integration("PUT", path, {"orderedFirewallPolicyIds": {
            "beforeSystemDefined": ids,
            "afterSystemDefined": (res.get("orderedFirewallPolicyIds") or {}).get(
                "afterSystemDefined") or []}})
        r.new("Reihenfolge korrigiert: RADIUS erlauben vor Verwaltungsnetz blocken [S9]")
    except (UniFiApiError, ValueError, AttributeError) as err:
        r.warn(f"Reihenfolge der RADIUS-Regeln nicht prüfbar ({err}) – in der UI kontrollieren [S9]")


# ---------------------------------------------------------------------- Anleitung
def guide_markdown(v: dict[str, Any], report: Report | None = None) -> str:
    f, net = v["firma"], v["net_name"]
    uni_ip = str(v["transfer"]).split("/")[0]
    soph = v["sophos_xfrm"]
    psk = v.get("psk") or "(in UniFi ablesen: Einstellungen → VPN → Site-to-Site → Pre-Shared Key)"
    rad = v.get("radius_secret") or "(in UniFi ablesen: Profile → RADIUS)"
    remote = ", ".join(v["remote_nets"])
    radl = ", ".join(v["radius_servers"])
    has_rad = bool(v["radius_servers"])
    stamp = dt_util.now().strftime("%d.%m.%Y %H:%M")
    L: list[str] = [
        f"# Sophos XGS – Gegenstelle für „{v['tunnel']}“", "",
        f"Erzeugt am {stamp} von UniFi Controller Manager (Controller {v['controller']})"
        + (" – **Vorschau, noch nichts angelegt**" if v.get("dry_run") else "") + ".", "",
        "## Werte", "", "| Parameter | Wert |", "|---|---|",
        f"| Öffentliche Adresse Sophos | {v['peer_fqdn']} ({v['peer_ip']}) |",
        f"| Öffentliche Adresse UniFi | {v['local_id']} (dynamisch → „Respond only“) |",
        f"| Local ID (Sophos) / Remote ID (UniFi) | FQDN `{v['peer_fqdn']}` / FQDN `{v['local_id']}` |",
        f"| Pre-Shared Key | `{psk}` |",
        f"| Transfernetz | {v['transfer_net']} – **Sophos xfrm: {soph}**, UniFi VTI: {v['transfer']} |",
        f"| Netz „{net}“ (UniFi) | **{v['firma_cidr']}** |",
        f"| {f}-Netze | {remote} |",
        f"| DNS für „{net}“ | {', '.join(v['remote_dns'])} |",
        f"| Internet für „{net}“ | "
        + ("**nur über die Sophos** (Full Tunnel, Kill-Switch auf UniFi-Seite)" if v["full_tunnel"]
           else "lokal über UniFi (Split Tunnel)") + " |",
    ]
    if has_rad:
        L += [f"| UniFi-Access-Points (RADIUS-Clients) | **{', '.join(v['ap_ips'])}** |",
              f"| RADIUS-Server | {radl} (Auth 1812, Acct 1813) |",
              f"| RADIUS Shared Secret | `{rad}` |", f"| WLAN | {v.get('ssid') or '–'} |"]
    L += ["", "> PSK und Shared Secret sind Geheimnisse – Dokument nach dem Einrichten löschen "
          "oder sicher ablegen.", "",
          "## 1. Objekte", "*Hosts and services → IP host*", "",
          "| Name | Typ | Wert |", "|---|---|---|",
          f"| `UniFi-Heim {net}` | Network | {v['firma_cidr']} |",
          f"| `UniFi-Heim Transfer` | IP | {uni_ip} |"]
    if has_rad:
        L += [f"| `UniFi-Heim APs` | IP list | {', '.join(v['ap_ips'])} |",
              f"| `{f} RADIUS` (falls nicht vorhanden) | IP list | {radl} |"]
    L += ["", "## 2. IPsec-Profil", "*Profiles → IPsec profiles → Add* – Name `UniFi-Heim-IKEv2`",
          "", "| Feld | Wert |", "|---|---|", "| Key exchange | **IKEv2** |",
          "| Authentication mode | Main mode |", "| Key negotiation tries | 0 (unbegrenzt) |",
          "| Re-key connection | an |", "| **Phase 1** Key life | 28800 s |",
          "| Phase 1 Encryption / Authentication | **AES256 / SHA2 256** |",
          "| Phase 1 DH group | **19 (ecp256)** – optional zusätzlich 14 |",
          "| **Phase 2** PFS group | **19 (ecp256)** |", "| Phase 2 Key life | 3600 s |",
          "| Phase 2 Encryption / Authentication | **AES256 / SHA2 256** |",
          "| Dead Peer Detection | an – Check 30 s, Wait 120 s, Action **Re-initiate** |", "",
          "## 3. IPsec-Verbindung (XFRM)", "*Site-to-site VPN → IPsec → Add* – Name `UniFi-Heim`",
          "", "| Feld | Wert |", "|---|---|", "| IP version | IPv4 |",
          "| Activate on save | **aus** (erst nach Schritt 8) |",
          "| Create firewall rule | aus (Regeln in Schritt 5) |",
          "| Connection type | **Tunnel interface** (erzeugt `xfrmN`) |",
          "| Gateway type | **Respond only** |", "| Profile | `UniFi-Heim-IKEv2` |",
          f"| Authentication type | Preshared key → `{psk}` |",
          f"| Listening interface | WAN-Port mit {v['peer_ip']} |",
          f"| Local ID type / Local ID | DNS / `{v['peer_fqdn']}` |",
          f"| Remote gateway | `{v['local_id']}` |",
          f"| Remote ID type / Remote ID | DNS / `{v['local_id']}` |",
          "| Local / Remote subnet | Any / Any (bei Tunnel interface automatisch) |", "",
          "## 4. XFRM-Interface und Routen",
          "*Network → Interfaces → xfrmN (zur Verbindung UniFi-Heim) → Edit*",
          f"- IPv4 **{soph}**, Zone **VPN**",
          "- MTU 1400 (oder TCP-MSS 1360), falls große Pakete hängen (RDP, Downloads, SMB)", "",
          f"*Routing → Static routes → IPv4 unicast → Add* (Interface **xfrmN**, Gateway **{uni_ip}**, "
          "Distance 0)", "", "| Ziel | Zweck |", "|---|---|",
          f"| {v['firma_cidr']} | Netz „{net}“ |"]
    if has_rad:
        L += [f"| {ip}/32 | RADIUS-Antworten an Access Point |" for ip in v["ap_ips"]]
    L += ["", "*Routing → Route precedence:* **Static routes vor SD-WAN routes** – sonst läuft "
          "Antwortverkehr ggf. über WAN statt xfrm.", "",
          "## 5. Firewall-Regeln",
          "*Rules and policies → Firewall rules → Add rule* (oberhalb allgemeiner VPN-Regeln)", "",
          "| # | Name | Quelle | Ziel | Dienste | Aktion |", "|---|---|---|---|---|---|",
          f"| 1 | UniFi-Heim {net} → {f}-Netze | Zone VPN, `UniFi-Heim {net}` | Zonen LAN/DMZ, "
          f"{f}-Netze | nach Firmenstandard | Accept, Log |"]
    n = 2
    if has_rad:
        L.append(f"| {n} | UniFi-Heim APs → RADIUS | Zone VPN, `UniFi-Heim APs` | `{f} RADIUS` | "
                 "**UDP 1812, 1813** | Accept |")
        n += 1
    if v["full_tunnel"]:
        L.append(f"| {n} | UniFi-Heim {net} → Internet | Zone VPN, `UniFi-Heim {net}` | Zone WAN | "
                 "Any (Web-/App-Filter, IPS wie Firmen-Clients) | Accept |")
        n += 1
    if v["allow_support"]:
        L.append(f"| {n} | {f}-Netze → UniFi-Heim {net} | Zone LAN, {f}-Netze | Zone VPN, "
                 f"`UniFi-Heim {net}` | Support-Dienste (RDP, SMB, Agenten) | Accept |")
    L += ["", "Nicht anlegen: Regeln von VPN Richtung andere Heimnetze – nur die oben genannten.", ""]
    if v["full_tunnel"]:
        L += ["## 6. NAT", "*Rules and policies → NAT rules*",
              f"- **SNAT** `UniFi-Heim {net} Internet`: Original source `UniFi-Heim {net}`, "
              "Outbound interface **WAN**, Translated source **MASQ**.",
              "- Standard-MASQ-Regel prüfen: Outbound interface **nur WAN**, nicht „Any“ – sonst "
              "wird Verkehr Richtung xfrm/LAN maskiert"
              + (" und der RADIUS-Server sieht die AP-Adressen nicht." if has_rad else "."),
              f"- **Kein** NAT für `UniFi-Heim {net}` → {f}-Netze"
              + (" und `UniFi-Heim APs` → RADIUS." if has_rad else "."), ""]
    else:
        L += ["## 6. NAT", f"- **Kein** NAT für `UniFi-Heim {net}` → {f}-Netze; Standard-MASQ nur "
              "auf WAN.", ""]
    if has_rad:
        L += [f"## 7. RADIUS / NPS (auf {radl})",
              "*NPS → RADIUS-Clients und -Server → RADIUS-Clients → Neu* – je Access Point:", "",
              "| Anzeigename | Adresse | Shared Secret |", "|---|---|---|"]
        L += [f"| UniFi-Heim {name} | {ip} | wie oben |" for name, ip in v["aps"]]
        if v.get("ssid"):
            L += ["", f"*Netzwerkrichtlinie* `WLAN UniFi-Heim ({v['ssid']})`:",
                  "- Bedingungen: Windows-Gruppe der Berechtigten · NAS-Porttyp **Wireless – IEEE "
                  f"802.11** · Called-Station-ID **`.*:{v['ssid']}$`** (UniFi sendet `BSSID:SSID`)",
                  "- Authentifizierung: **EAP-TLS** (Computerzertifikat) oder PEAP-MSCHAPv2 – wie "
                  "im Firmen-WLAN",
                  f"- Kein VLAN-Attribut nötig – das WLAN ist fest an Netz „{net}“ gebunden",
                  "- Accounting aktivieren (Port 1813), falls protokolliert werden soll"]
        L.append("")
    L += ["## 8. Aktivieren und testen",
          "1. Sophos: Verbindung `UniFi-Heim` **aktivieren** (Respond only – wartet auf UniFi).",
          f"2. UniFi: *Einstellungen → VPN → Site-to-Site → {v['tunnel']}* – **Key Exchange = "
          "IKEv2** prüfen, **aktivieren**.",
          f"3. Sophos: *Site-to-site VPN → IPsec* → Status grün; *Diagnostics → Ping* auf "
          f"**{uni_ip}** (über xfrmN)."]
    if v.get("ssid"):
        L.append(f"4. UniFi: WLAN **„{v['ssid']}“ aktivieren**, Firmengerät verbinden: IP aus "
                 f"**{v['firma_cidr']}**, DNS {' / '.join(v['remote_dns'])}, Firmenressourcen "
                 "erreichbar" + (", öffentliche IP = die der Firma" if v["full_tunnel"] else "") + ".")
    L += ["5. Gegenproben:", f"   - aus dem Heimnetz **kein** Zugriff auf {remote}",
          f"   - aus „{net}“ **kein** Zugriff auf Heimnetze"]
    if v["full_tunnel"]:
        L.append(f"   - Tunnel deaktivieren → „{net}“ hat **kein** Internet (Kill-Switch)")
    L += ["", "## 9. Fehlersuche", "", "| Symptom | Ursache / Prüfung |", "|---|---|",
          "| Phase 1 kommt nicht hoch, `AUTHENTICATION_FAILED` | PSK oder IDs (FQDN beidseitig) |",
          "| `NO_PROPOSAL_CHOSEN` | IKEv2, AES256/SHA2 256, DH 19 beidseitig; UniFi auf IKEv1? |",
          "| Tunnel oben, kein Verkehr | Statische Routen auf xfrmN, Route precedence, Regel 1 |",
          f"| Ping auf {uni_ip} geht nicht | xfrm-IP/Maske, Zone VPN, UniFi-Tunnel aktiv |"]
    if has_rad:
        L += ["| WLAN-Anmeldung hängt | NPS-Clients = AP-IPs, RADIUS-Regel, /32-Routen, MASQ nur WAN |",
              "| NPS-Ereignis 6273 „Grund 16/48“ | Netzwerkrichtlinie (Gruppe, Called-Station-ID, EAP) |"]
    if v["full_tunnel"]:
        L.append(f"| Verbunden, aber kein Internet | SNAT für {v['firma_cidr']}, Internet-Regel |")
    L += ["| Abbrüche bei RDP/Downloads | MTU 1400 / MSS 1360 auf xfrmN |",
          f"| Tunnel bricht nach IP-Wechsel der UniFi ab | DPD Re-initiate, Remote gateway als "
          f"FQDN ({v['local_id']}) |"]
    if report is not None:
        L += ["", "## Anhang: Ergebnis auf der UniFi-Seite", "", report.markdown()]
    return "\n".join(L) + "\n"


def guide_html(md: str, title: str) -> str:
    """Kleines, druckbares HTML ohne externe Abhängigkeiten (Tabellen, Listen, Code, Fett)."""
    import re  # noqa: PLC0415

    def inline(t: str) -> str:
        t = html.escape(t)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
        return re.sub(r"\*([^*]+)\*", r"<i>\1</i>", t)

    out: list[str] = []
    table: list[list[str]] = []
    lst = False

    def flush() -> None:
        nonlocal table, lst
        if table:
            out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in table[0])
                       + "</tr></thead><tbody>" + "".join(
                           "<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>"
                           for row in table[1:]) + "</tbody></table>")
            table = []
        if lst:
            out.append("</ul>")
            lst = False

    for line in md.splitlines():
        s = line.strip()
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not all(set(c) <= set("-: ") for c in cells):
                table.append(cells)
            continue
        if s.startswith("- ") or re.match(r"^\d+\. ", s):
            if table:
                flush()
            if not lst:
                out.append("<ul>")
                lst = True
            item = re.sub(r"^(- |\d+\. )", "", s)
            out.append(f"<li>{inline(item)}</li>")
            continue
        flush()
        if s.startswith("#"):
            lvl = len(s) - len(s.lstrip("#"))
            out.append(f"<h{lvl}>{inline(s.lstrip('#').strip())}</h{lvl}>")
        elif s.startswith(">"):
            out.append(f"<blockquote>{inline(s.lstrip('> '))}</blockquote>")
        elif s:
            out.append(f"<p>{inline(s)}</p>")
    flush()
    css = ("body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:960px;"
           "margin:24px auto;padding:0 16px;color:#1b1f24;line-height:1.45}"
           "h1{font-size:1.6em;border-bottom:2px solid #0b62a4;padding-bottom:6px}"
           "h2{font-size:1.2em;margin-top:1.6em;color:#0b62a4}"
           "table{border-collapse:collapse;width:100%;margin:8px 0;font-size:.92em}"
           "th,td{border:1px solid #cfd6de;padding:5px 8px;text-align:left;vertical-align:top}"
           "th{background:#eef3f8}code{background:#f2f4f7;padding:1px 4px;border-radius:3px;"
           "word-break:break-all}blockquote{border-left:4px solid #d97706;margin:8px 0;"
           "padding:6px 12px;background:#fff7ed}@media print{h2{page-break-after:avoid}"
           "table{page-break-inside:avoid}}")
    return (f"<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)}</title><style>{css}</style></head><body>"
            + "\n".join(out) + "</body></html>")


def save_guide(config_dir: str, sub_id: str, md: str, title: str) -> tuple[str, str]:
    """Anleitung unter /config/unifi_controller/site_to_site/ ablegen (nicht öffentlich)."""
    folder = os.path.join(config_dir, DOC_DIR)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    md_path = os.path.join(folder, f"{sub_id}.md")
    html_path = os.path.join(folder, f"{sub_id}.html")
    for path, content in ((md_path, md), (html_path, guide_html(md, title))):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(path, 0o600)
    return md_path, html_path


def doc_url(hass, entry_id: str, sub_id: str, fmt: str = "html", hours: int = 24) -> str:
    """Signierter Download-Link (nur angemeldet erzeugbar, begrenzt gültig)."""
    from datetime import timedelta  # noqa: PLC0415

    from homeassistant.components.http.auth import async_sign_path  # noqa: PLC0415

    return async_sign_path(hass, f"/api/{DOMAIN}/s2s/{entry_id}/{sub_id}.{fmt}",
                           timedelta(hours=hours))


# ---------------------------------------------------------------------- Ablage, Link, Meldung
def slug(text: str) -> str:
    import re  # noqa: PLC0415

    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "tunnel"


async def async_publish(coordinator: UniFiCoordinator, cfg: S2SConfig, report: Report,
                        notify: bool = True) -> dict[str, Any]:
    """Anleitung speichern, signierten Link erzeugen, optional HA-Benachrichtigung."""
    hass = coordinator.hass
    name = slug(cfg.firma)
    md = guide_markdown(report.values, report)
    title = f"Sophos XGS – {cfg.tunnel}"
    md_path, _ = await hass.async_add_executor_job(
        save_guide, hass.config.config_dir, name, md, title)
    entry_id = coordinator.config_entry.entry_id
    url_html = doc_url(hass, entry_id, name, "html")
    url_md = doc_url(hass, entry_id, name, "md")
    if notify:
        from homeassistant.components import persistent_notification as pn  # noqa: PLC0415

        lines = [f"**{cfg.tunnel}** – UniFi-Seite " + (
            "eingerichtet." if report.apply else "geprüft (Vorschau, nichts angelegt).")]
        if report.created:
            lines.append("\n**" + ("Angelegt" if report.apply else "Würde angelegt") + ":**")
            lines += [f"- {t}" for t in report.created]
        if report.renamed:
            lines.append("\n**" + ("Umbenannt" if report.apply else "Würde umbenannt") + ":**")
            lines += [f"- {t}" for t in report.renamed]
        if report.warnings:
            lines.append("\n**Hinweise:**")
            lines += [f"- {t}" for t in report.warnings]
        lines.append(f"\n**Anleitung für die Sophos:** [HTML (druckbar)]({url_html}) · "
                     f"[Markdown]({url_md}) – Links 24 h gültig, neu erzeugen mit "
                     "`unifi_controller.site_to_site_document`. Datei: `" + md_path + "`")
        if report.secrets:
            lines.append("\n⚠️ Die Anleitung enthält PSK/Shared Secret – nach dem Einrichten löschen "
                         "oder sicher ablegen.")
        lines.append("\nAktivieren bewusst von Hand: 1. Sophos fertig · 2. Tunnel aktivieren · "
                     "3. WLAN aktivieren")
        pn.async_create(hass, "\n".join(lines), title=f"Site-to-Site {cfg.firma}",
                        notification_id=f"{DOMAIN}_s2s_{name}")
    return {"anleitung_html": url_html, "anleitung_md": url_md, "datei": md_path,
            "angelegt": report.created, "umbenannt": report.renamed,
            "hinweise": report.warnings,
            "ablauf": [f"{s}: {t}" for s, t in report.steps]}


def register_view(hass) -> None:
    """Download der Anleitung – nur mit Anmeldung bzw. signiertem Link."""
    from aiohttp import web  # noqa: PLC0415

    from homeassistant.components.http import HomeAssistantView  # noqa: PLC0415

    class S2SDocView(HomeAssistantView):
        url = f"/api/{DOMAIN}/s2s/{{entry_id}}/{{name}}.{{fmt}}"
        name = f"api:{DOMAIN}:s2s"
        requires_auth = True

        async def get(self, request: web.Request, entry_id: str, name: str,
                      fmt: str) -> web.Response:
            if fmt not in ("html", "md") or name != slug(name):
                return web.Response(status=404)
            entry = hass.config_entries.async_get_entry(entry_id)
            if entry is None or entry.domain != DOMAIN:
                return web.Response(status=404)
            path = os.path.join(hass.config.config_dir, DOC_DIR, f"{name}.{fmt}")

            def read() -> str | None:
                try:
                    with open(path, encoding="utf-8") as fh:
                        return fh.read()
                except OSError:
                    return None
            text = await hass.async_add_executor_job(read)
            if text is None:
                return web.Response(status=404)
            if fmt == "html":
                return web.Response(text=text, content_type="text/html", charset="utf-8",
                                    headers={"Cache-Control": "no-store"})
            return web.Response(
                text=text, content_type="text/markdown", charset="utf-8",
                headers={"Cache-Control": "no-store",
                         "Content-Disposition": f'attachment; filename="Sophos-{name}.md"'})

    hass.http.register_view(S2SDocView())
