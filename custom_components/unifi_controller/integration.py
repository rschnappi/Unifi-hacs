"""Offizielle UniFi Network API (integration/v1, ab Network 9 – Stand 11.0.89).

Ergänzt die interne Legacy-/v2-API dort, wo die offizielle API mehr kann oder stabiler ist:
Hotspot-Gutscheine, Geräte-Übernahme, ACL-Regeln (Switch-ACLs), Firewall-Logging (PATCH),
Live-Statistik von Geräten und eine Reihe nur lesbarer Ressourcen (WANs, VPN-Server,
Site-to-Site-Tunnel, RADIUS-Profile, Geräte-Tags, Switch-Stacks, LAGs …).
Alle Abrufe sind „best effort“: ein Controller ohne diese API läuft unverändert weiter.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.components.switch import SwitchEntity
from homeassistant.exceptions import HomeAssistantError

from .api import UniFiApiError
from .const import DOMAIN, EVENT_NEW_CLIENT
from .entity import ControllerEntity

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

# Ressource -> Pfad relativ zu integration/v1 ({site} = Site-UUID); nur lesend über get_objects
RESOURCES: dict[str, str] = {
    "int_devices": "sites/{site}/devices",
    "int_clients": "sites/{site}/clients",
    "int_networks": "sites/{site}/networks",
    "wifi_broadcasts": "sites/{site}/wifi/broadcasts",
    "int_firewall_zones": "sites/{site}/firewall/zones",
    "int_firewall_policies": "sites/{site}/firewall/policies",
    "acl_rules": "sites/{site}/acl-rules",
    "dns_policies": "sites/{site}/dns/policies",
    "traffic_matching_lists": "sites/{site}/traffic-matching-lists",
    "vouchers": "sites/{site}/hotspot/vouchers",
    "pending_devices": "pending-devices",
    "wans": "sites/{site}/wans",
    "vpn_servers": "sites/{site}/vpn/servers",
    "site_to_site_tunnels": "sites/{site}/vpn/site-to-site-tunnels",
    "radius_profiles": "sites/{site}/radius/profiles",
    "device_tags": "sites/{site}/device-tags",
    "switch_stacks": "sites/{site}/switching/switch-stacks",
    "mc_lag_domains": "sites/{site}/switching/mc-lag-domains",
    "lags": "sites/{site}/switching/lags",
    "dpi_categories": "dpi/categories",
    "dpi_applications": "dpi/applications",
    "countries": "countries",
}
# im Konfigurations-Zyklus mitgeladen (für Entitäten)
POLLED = ("vouchers", "pending_devices", "acl_rules", "int_devices")
VOUCHER_PAGE = 1000
READ_ONLY = {"id", "metadata", "index"}


def _key(item: dict, i: int) -> str:
    return str(item.get("id") or item.get("macAddress") or item.get("code") or i)


async def async_fetch(coordinator: UniFiCoordinator, out: dict[str, dict[str, dict]],
                      prev: dict[str, dict[str, dict]]) -> None:
    """Integration-Datensätze in die Konfiguration übernehmen (bei Fehler: letzte Daten)."""
    import asyncio  # noqa: PLC0415

    client = coordinator.client
    jobs = {
        name: client.integration_list(
            RESOURCES[name], page=VOUCHER_PAGE if name == "vouchers" else 200)
        for name in POLLED
    }
    results = await asyncio.gather(*jobs.values(), return_exceptions=True)
    failed = coordinator._failed  # noqa: SLF001
    for name, res in zip(jobs, results, strict=True):
        if isinstance(res, BaseException):
            if f"int:{name}" not in failed:
                _LOGGER.debug("Integration-API %s nicht verfügbar: %s", name, res)
                failed.add(f"int:{name}")
            if name in prev:          # noch nie geladen → Schlüssel weglassen (keine Entitäten)
                out[name] = prev[name]
            continue
        failed.discard(f"int:{name}")
        out[name] = {_key(item, i): item for i, item in enumerate(res)}
    _announce_pending(coordinator, prev.get("pending_devices"), out.get("pending_devices", {}))


def _announce_pending(coordinator: UniFiCoordinator, before: dict | None, now: dict) -> None:
    """Neues Gerät wartet auf Übernahme → Event + Benachrichtigung (Kategorie „Neue Geräte“)."""
    if before is None:            # erster Abruf: nur merken
        return
    hass = coordinator.hass
    for mac, dev in now.items():
        if mac in before:
            continue
        info = {"mac": dev.get("macAddress"), "model": dev.get("model"),
                "ip": dev.get("ipAddress"), "state": dev.get("state"),
                "firmware": dev.get("firmwareVersion"), "pending_adoption": True}
        hass.bus.async_fire(EVENT_NEW_CLIENT, info)
        from .notifications import async_send  # noqa: PLC0415

        hass.async_create_task(async_send(
            hass, coordinator.config_entry.options, "new_device",
            "UniFi-Gerät wartet auf Übernahme",
            f"**{info['model'] or 'Gerät'}** ({info['mac']}, {info['ip'] or '–'}) kann "
            f"übernommen werden.\n\nÜbernehmen: Dienst `{DOMAIN}.adopt_device` mit dieser MAC.",
            {"tag": f"pending_{info['mac']}"}))


# --------------------------------------------------------------------- Helfer
def device_uuid(coordinator: UniFiCoordinator, mac: str) -> str:
    """UUID eines übernommenen Geräts (offizielle API) zur MAC."""
    mac = mac.lower()
    for dev in coordinator.data.config.get("int_devices", {}).values():
        if str(dev.get("macAddress", "")).lower() == mac:
            return dev["id"]
    raise UniFiApiError(f"Gerät {mac} in der Integration-API nicht gefunden")


def format_code(code: Any) -> str:
    s = str(code or "")
    return f"{s[:5]}-{s[5:]}" if len(s) == 10 and s.isdigit() else s


def voucher_view(v: dict) -> dict[str, Any]:
    return {
        "id": v.get("id"), "name": v.get("name"), "code": format_code(v.get("code")),
        "minutes": v.get("timeLimitMinutes"), "guests": v.get("authorizedGuestCount"),
        "guest_limit": v.get("authorizedGuestLimit"), "expired": v.get("expired"),
        "activated": v.get("activatedAt"), "expires": v.get("expiresAt"),
        "data_mb": v.get("dataUsageLimitMBytes"), "down_kbps": v.get("rxRateLimitKbps"),
        "up_kbps": v.get("txRateLimitKbps"), "created": v.get("createdAt"),
    }


def quote_filter(value: str) -> str:
    """String für den Filter der offiziellen API ('…', ' verdoppelt)."""
    return "'" + str(value).replace("'", "''") + "'"


def body_of(obj: dict, changes: dict) -> dict:
    """PUT-Body: Objekt ohne nur lesbare Felder + Änderungen."""
    return {k: v for k, v in obj.items() if k not in READ_ONLY} | changes


# ------------------------------------------------------------------ Entitäten
class VoucherSensor(ControllerEntity, SensorEntity):
    """Gültige (nicht abgelaufene) Hotspot-Gutscheine."""

    _attr_icon = "mdi:ticket-confirmation"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "Gutscheine"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "hotspot_vouchers", "Hotspot-Gutscheine")

    def _valid(self) -> list[dict]:
        return [v for v in self.coordinator.data.config.get("vouchers", {}).values()
                if not v.get("expired")]

    @property
    def native_value(self) -> int:
        return len(self._valid())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        valid = sorted(self._valid(), key=lambda v: v.get("createdAt") or "", reverse=True)
        allv = self.coordinator.data.config.get("vouchers", {})
        return {"gutscheine": [voucher_view(v) for v in valid[:50]],
                "in_benutzung": sum(1 for v in valid if v.get("activatedAt")),
                "abgelaufen": len(allv) - len(valid)}


class PendingDevicesSensor(ControllerEntity, SensorEntity):
    """UniFi-Geräte, die auf Übernahme (Adoption) warten."""

    _attr_icon = "mdi:access-point-plus"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "Geräte"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "pending_devices", "Geräte zur Übernahme")

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data.config.get("pending_devices", {}))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"geraete": [
            {"mac": d.get("macAddress"), "modell": d.get("model"), "ip": d.get("ipAddress"),
             "zustand": d.get("state"), "firmware": d.get("firmwareVersion"),
             "unterstuetzt": d.get("supported")}
            for d in self.coordinator.data.config.get("pending_devices", {}).values()]}


class AclRuleSwitch(ControllerEntity, SwitchEntity):
    """ACL-Regel (Switch-ACL) ein/aus – offizielle API."""

    _attr_icon = "mdi:shield-check-outline"

    def __init__(self, coordinator: UniFiCoordinator, rule_id: str) -> None:
        from .resources import name_key  # noqa: PLC0415

        rule = coordinator.data.config["acl_rules"][rule_id]
        super().__init__(coordinator, f"acl_name_{name_key({'name': rule.get('name')})}",
                         f"ACL {rule.get('name') or rule_id}")
        self._id = rule_id
        self._name = rule.get("name")

    @property
    def _rule(self) -> dict | None:
        rules = self.coordinator.data.config.get("acl_rules", {})
        if (r := rules.get(self._id)) is not None:
            return r
        for rid, r in rules.items():          # neu angelegt: gleichnamige übernehmen
            if r.get("name") == self._name:
                self._id = rid
                return r
        return None

    @property
    def available(self) -> bool:
        return super().available and self._rule is not None

    @property
    def is_on(self) -> bool:
        return bool((self._rule or {}).get("enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        r = self._rule or {}
        return {"id": r.get("id"), "typ": r.get("type"), "aktion": r.get("action"),
                "beschreibung": r.get("description"), "protokolle": r.get("protocolFilter"),
                "quelle": r.get("sourceFilter"), "ziel": r.get("destinationFilter")}

    async def _set(self, on: bool) -> None:
        rule = self._rule
        if rule is None:
            raise HomeAssistantError("ACL-Regel nicht mehr vorhanden")
        try:
            await self.coordinator.async_command(self.coordinator.client.integration(
                "PUT", f"sites/{{site}}/acl-rules/{rule['id']}", body_of(rule, {"enabled": on})))
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)


def sensors(coordinator: UniFiCoordinator):
    cfg = coordinator.data.config
    if "vouchers" in cfg:
        yield VoucherSensor(coordinator)
    if "pending_devices" in cfg:
        yield PendingDevicesSensor(coordinator)


def switches(coordinator: UniFiCoordinator):
    for rid, rule in coordinator.data.config.get("acl_rules", {}).items():
        if (rule.get("metadata") or {}).get("origin") != "SYSTEM_DEFINED":
            yield AclRuleSwitch(coordinator, rid)
