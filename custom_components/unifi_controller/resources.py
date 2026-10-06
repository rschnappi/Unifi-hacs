"""Beschreibung aller Konfigurationsobjekte des Controllers (Datasets + Schalter)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# dataset -> API-Pfad (Legacy relativ zu /api/s/<site>/, v2/… = v2-API)
DATASETS: dict[str, str] = {
    "networks": "rest/networkconf",
    "wlans": "rest/wlanconf",
    "firewall_policies": "v2/firewall-policies",
    "firewall_zones": "v2/firewall/zone",
    "firewall_groups": "rest/firewallgroup",
    "trafficrules": "v2/trafficrules",
    "trafficroutes": "v2/trafficroutes",
    "portforwards": "rest/portforward",
    "routes": "rest/routing",
    "dns_records": "v2/static-dns",
    "port_profiles": "rest/portconf",
    "usergroups": "rest/usergroup",
    "qos_rules": "v2/qos-rules",
    "settings": "rest/setting",
    "users": "rest/user",
}
OPTIONAL_DATASETS = {"users"}  # nur mit Client-Sperr-Schaltern

VPN_PURPOSES = {"remote-user-vpn", "vpn-client", "site-vpn"}
LAN_PURPOSES = {"corporate", "guest"}

# Felder, die nie in Attribute/Antworten gehören bzw. sich ständig ändern
VOLATILE = {"hits", "last_hit"}
SKIP_ATTRS = VOLATILE | {"site_id", "external_id", "_id", "attr_hidden_id"}

SECRET_WORDS = ("key", "psk", "token", "secret", "password", "passphrase",
                "certificate", "private", "passwd")


def is_secret(key: str) -> bool:
    """x_*-Felder und alles, was nach Schlüssel/Passwort/Zertifikat aussieht."""
    k = key.lower()
    if key.startswith("x_"):
        return True
    if k in ("key", "public_key") or k.endswith("_public_key") or k.endswith("_key_id"):
        return False
    return any(w in k for w in SECRET_WORDS)


def redact(obj: Any) -> Any:
    """Geheimnisse (Passwörter, Keys, PSKs, Tokens, Zertifikate …) rekursiv entfernen."""
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items() if not is_secret(k)}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def object_name(obj: dict) -> str:
    return str(
        obj.get("name") or obj.get("description") or obj.get("key")
        or obj.get("hostname") or obj.get("_id", "?")
    ).strip()


def scalar_attrs(obj: dict) -> dict[str, Any]:
    return {
        k: v for k, v in obj.items()
        if not is_secret(k) and k not in SKIP_ATTRS
        and (v is None or isinstance(v, (str, int, float, bool)))
    } | {"id": obj.get("_id")}


def _fw_attrs(obj: dict, config: dict[str, dict[str, dict]]) -> dict[str, Any]:
    zones = config.get("firewall_zones", {})
    src, dst = obj.get("source") or {}, obj.get("destination") or {}

    def side(s: dict) -> dict[str, Any]:
        return {
            "zone": zones.get(s.get("zone_id", ""), {}).get("name", s.get("zone_id")),
            "target": s.get("matching_target"),
            "ips": s.get("ips"),
            "port": s.get("port"),
        }

    return scalar_attrs(obj) | {
        "source": side(src),
        "destination": side(dst),
        "schedule": (obj.get("schedule") or {}).get("mode"),
    }


@dataclass(frozen=True, kw_only=True)
class SwitchGroup:
    """Eine Schaltergruppe über einem Dataset."""

    key: str
    dataset: str
    label: str
    field: str = "enabled"
    suffix: str = ""
    uid: str | None = None
    by_name: bool = False   # Unique-ID am Namen statt an der UniFi-ID (übersteht Neuanlage)
    icon: str = "mdi:toggle-switch"
    filter: Callable[[dict], bool] = lambda o: True
    attrs: Callable[[dict, dict], dict] = lambda o, c: scalar_attrs(o)

    @property
    def uid_prefix(self) -> str:
        return self.uid or self.key


SWITCH_GROUPS: tuple[SwitchGroup, ...] = (
    SwitchGroup(key="wlans", dataset="wlans", label="WLAN", uid="wlan", icon="mdi:wifi"),
    SwitchGroup(
        key="networks", dataset="networks", label="Netzwerk", uid="network",
        icon="mdi:lan",
        filter=lambda o: o.get("purpose") in LAN_PURPOSES and not o.get("attr_no_delete"),
    ),
    SwitchGroup(
        key="networks_internet", dataset="networks", label="Netzwerk", suffix=" Internet",
        field="internet_access_enabled", uid="network_internet", icon="mdi:web",
        filter=lambda o: o.get("purpose") in LAN_PURPOSES and "internet_access_enabled" in o,
    ),
    SwitchGroup(
        key="vpn", dataset="networks", label="VPN", icon="mdi:vpn",
        filter=lambda o: o.get("purpose") in VPN_PURPOSES,
    ),
    SwitchGroup(
        key="firewall_policies", dataset="firewall_policies", label="FW",
        icon="mdi:shield-lock", filter=lambda o: not o.get("predefined"), attrs=_fw_attrs,
        by_name=True,
    ),
    SwitchGroup(key="trafficrules", dataset="trafficrules", label="Traffic-Regel",
                icon="mdi:traffic-light", by_name=True,
                filter=lambda o: not str(o.get("description", "")).startswith("HA App-Sperre")),
    SwitchGroup(key="trafficroutes", dataset="trafficroutes", label="Traffic-Route",
                icon="mdi:routes", by_name=True),
    SwitchGroup(key="portforwards", dataset="portforwards", label="Portweiterleitung",
                icon="mdi:router-network"),
    SwitchGroup(key="qos_rules", dataset="qos_rules", label="QoS", icon="mdi:speedometer",
                by_name=True),
    SwitchGroup(key="routes", dataset="routes", label="Route", icon="mdi:routes"),
    SwitchGroup(key="dns_records", dataset="dns_records", label="DNS", icon="mdi:dns"),
)
SWITCH_GROUP_KEYS = [g.key for g in SWITCH_GROUPS]


def name_key(obj: dict) -> str:
    """Stabiler Schlüssel aus dem Objektnamen (für Unique-IDs)."""
    from homeassistant.util import slugify  # noqa: PLC0415

    return slugify(object_name(obj)) or str(obj.get("_id", ""))


def stable_id(obj: dict | None, fallback: str = "") -> str:
    """Stabile Objekt-ID für Unique-IDs.

    Ab Network 11 (PostgreSQL) haben alle Objekte eine neue UUID als ``_id``; die frühere
    Mongo-ID steht in ``legacy_id``. Für Entitäten wird die alte ID weiterverwendet, damit sie
    nach dem Update dieselben bleiben. API-Aufrufe nutzen immer ``_id``.
    """
    obj = obj or {}
    return str(obj.get("legacy_id") or obj.get("_id") or fallback)


def switch_suffix(group: SwitchGroup, obj_id: str, obj: dict) -> str:
    """Unique-ID-Suffix eines Schalters."""
    if group.by_name:
        return f"{group.uid_prefix}_name_{name_key(obj)}"
    return f"{group.uid_prefix}_{stable_id(obj, obj_id)}"
