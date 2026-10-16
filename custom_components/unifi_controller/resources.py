"""Beschreibung aller Konfigurationsobjekte des Controllers (Datasets + Schalter)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# dataset -> API-Pfad (Legacy relativ zu /api/s/<site>/, v2/… = v2-API)
DATASETS: dict[str, str] = {
    "networks": "rest/networkconf",
    "wlans": "rest/wlanconf",
    "legacy_zones": "v2/firewall/zone",      # nur für die Zuordnung Netz → Zone (interne IDs)
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

# dataset -> Pfad der offiziellen API (relativ zu integration/v1, {site} = Site-UUID).
# Objekte bekommen zusätzlich "_id" = "id", damit Schalter, Suche und Dienste einheitlich bleiben.
OFFICIAL: dict[str, str] = {
    "firewall_policies": "sites/{site}/firewall/policies",
    "firewall_zones": "sites/{site}/firewall/zones",
    "firewall_groups": "sites/{site}/traffic-matching-lists",
}
# Hilfsfelder, die nie zurückgeschrieben werden
LOCAL_FIELDS = {"_id", "internal_zone_id", "internal_network_ids"}
OFFICIAL_READ_ONLY = {"id", "metadata", "index"} | LOCAL_FIELDS


SYSTEM_ORIGINS = {"SYSTEM_DEFINED", "DERIVED"}   # DERIVED = automatische Rückverkehr-Regel


def is_system(obj: dict) -> bool:
    """Nicht selbst angelegt: vom System oder automatisch abgeleitet (z. B. „… (Return)“)."""
    return bool(obj.get("predefined")) or \
        (obj.get("metadata") or {}).get("origin") in SYSTEM_ORIGINS


def official_body(obj: dict, changes: dict | None = None) -> dict:
    """PUT-Body der offiziellen API: Objekt ohne nur lesbare Felder + Änderungen."""
    return {k: v for k, v in obj.items() if k not in OFFICIAL_READ_ONLY} | (changes or {})

VPN_PURPOSES = {"remote-user-vpn", "vpn-client", "site-vpn"}
LAN_PURPOSES = {"corporate", "guest"}

# Felder, die nie in Attribute/Antworten gehören bzw. sich ständig ändern
VOLATILE = {"hits", "last_hit"}
SKIP_ATTRS = VOLATILE | {"site_id", "external_id", "_id", "attr_hidden_id", "internal_zone_id"}

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


def _filter_text(tf: dict | None) -> str | None:
    """Traffic-Filter der offiziellen API kurz beschreiben."""
    if not tf:
        return None
    kind = tf.get("type")
    if kind == "REGION":
        return "Länder " + ", ".join((tf.get("regionFilter") or {}).get("regions") or [])
    parts = []
    ipf = tf.get("ipAddressFilter") or {}
    if ipf.get("type") == "TRAFFIC_MATCHING_LIST":
        parts.append("Liste")
    elif ipf.get("items"):
        parts.append(", ".join(str(i.get("value")) for i in ipf["items"]))
    pf = tf.get("portFilter") or {}
    if pf.get("items"):
        parts.append("Port " + ", ".join(
            str(i.get("value") or f"{i.get('start')}-{i.get('stop')}") for i in pf["items"]))
    if (ipf or pf).get("matchOpposite"):
        parts.insert(0, "nicht")
    return " ".join(parts) or kind


def _fw_attrs(obj: dict, config: dict[str, dict[str, dict]]) -> dict[str, Any]:
    zones = config.get("firewall_zones", {})
    lists = config.get("firewall_groups", {})

    def side(s: dict) -> dict[str, Any]:
        tf = s.get("trafficFilter") or {}
        lid = (tf.get("ipAddressFilter") or {}).get("trafficMatchingListId")
        return {
            "zone": zones.get(s.get("zoneId", ""), {}).get("name", s.get("zoneId")),
            "filter": _filter_text(tf),
            "liste": lists.get(lid, {}).get("name") if lid else None,
        }

    return {
        "id": obj.get("id"), "enabled": obj.get("enabled"), "name": obj.get("name"),
        "description": obj.get("description"),
        "action": (obj.get("action") or {}).get("type"),
        "source": side(obj.get("source") or {}),
        "destination": side(obj.get("destination") or {}),
        "ip_version": (obj.get("ipProtocolScope") or {}).get("ipVersion"),
        "connection_states": obj.get("connectionStateFilter"),
        "logging": obj.get("loggingEnabled"),
        "flows": obj.get("reportFlowEnabled"),
        "schedule": (obj.get("schedule") or {}).get("mode", "ALWAYS"),
        "index": obj.get("index"),
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
        icon="mdi:shield-lock", filter=lambda o: not is_system(o), attrs=_fw_attrs,
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


def switch_suffix(group: SwitchGroup, obj_id: str, obj: dict) -> str:
    """Unique-ID-Suffix eines Schalters."""
    if group.by_name:
        return f"{group.uid_prefix}_name_{name_key(obj)}"
    return f"{group.uid_prefix}_{obj_id}"
