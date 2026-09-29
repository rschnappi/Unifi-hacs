"""Schalter: WLANs, LED, Lokalisieren, PoE, Client-Sperre, Regeln."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import (
    CONF_CLIENT_SWITCHES,
    CONF_FIREWALL_POLICIES,
    CONF_PORTFORWARDS,
    CONF_TRAFFICRULES,
)
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    opts = entry.options

    def factory():
        data = coordinator.data
        for wlan_id in data.wlans:
            yield WlanSwitch(coordinator, wlan_id)
        for mac, dev in data.devices.items():
            if "led_override" in dev:
                yield LedSwitch(coordinator, mac)
            yield LocateSwitch(coordinator, mac)
            for port in dev.get("port_table", []):
                if port.get("port_poe"):
                    yield PoeSwitch(coordinator, mac, port["port_idx"])
        if opts.get(CONF_CLIENT_SWITCHES):
            for mac, user in data.users.items():
                if user.get("name"):
                    yield ClientBlockSwitch(coordinator, mac)
        if opts.get(CONF_PORTFORWARDS):
            for rid in data.portforwards:
                yield RuleSwitch(coordinator, "portforwards", rid)
        if opts.get(CONF_TRAFFICRULES):
            for rid in data.trafficrules:
                yield RuleSwitch(coordinator, "trafficrules", rid)
        if opts.get(CONF_FIREWALL_POLICIES):
            for rid, pol in data.firewall_policies.items():
                if not pol.get("predefined"):
                    yield RuleSwitch(coordinator, "firewall_policies", rid)

    async_add_dynamic(coordinator, async_add_entities, factory)


# --------------------------------------------------------------------- WLAN
class WlanSwitch(ControllerEntity, SwitchEntity):
    _attr_icon = "mdi:wifi"

    def __init__(self, coordinator: UniFiCoordinator, wlan_id: str) -> None:
        name = coordinator.data.wlans[wlan_id].get("name", wlan_id)
        super().__init__(coordinator, f"wlan_{wlan_id}", f"WLAN {name}")
        self._id = wlan_id

    @property
    def _wlan(self) -> dict | None:
        return self.coordinator.data.wlans.get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._wlan is not None

    @property
    def is_on(self) -> bool:
        return bool((self._wlan or {}).get("enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        w = self._wlan or {}
        return {"ssid": w.get("name"), "security": w.get("security"),
                "is_guest": w.get("is_guest"), "networkconf_id": w.get("networkconf_id")}

    async def _set(self, enabled: bool) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.update_wlan(self._id, {"enabled": enabled})
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)


# ------------------------------------------------------------------- Geräte
class LedSwitch(DeviceEntity, SwitchEntity):
    _attr_icon = "mdi:led-on"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "led", "LED")

    @property
    def is_on(self) -> bool:
        return (self.device or {}).get("led_override") != "off"

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.set_led(self.device["_id"], "on"))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.set_led(self.device["_id"], "off"))


class LocateSwitch(DeviceEntity, SwitchEntity):
    _attr_icon = "mdi:crosshairs-gps"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "locate", "Lokalisieren")

    @property
    def is_on(self) -> bool:
        return bool((self.device or {}).get("locating"))

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("set-locate", self._mac))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("unset-locate", self._mac))


class PoeSwitch(DeviceEntity, SwitchEntity):
    _attr_icon = "mdi:ethernet"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, mac: str, port_idx: int) -> None:
        super().__init__(coordinator, mac, f"poe_{port_idx}", f"Port {port_idx} PoE")
        self._idx = port_idx

    @property
    def _port(self) -> dict:
        for port in (self.device or {}).get("port_table", []):
            if port.get("port_idx") == self._idx:
                return port
        return {}

    @property
    def is_on(self) -> bool:
        return self._port.get("poe_mode", "off") != "off"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self._port
        return {"port_name": p.get("name"), "poe_mode": p.get("poe_mode")}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.set_port_poe(self.device, self._idx, "auto"))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.set_port_poe(self.device, self._idx, "off"))


# ------------------------------------------------------------------ Clients
class ClientBlockSwitch(ControllerEntity, SwitchEntity):
    """EIN = Client gesperrt."""

    _attr_icon = "mdi:account-cancel"

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        name = coordinator.data.users[mac].get("name", mac)
        super().__init__(coordinator, f"block_{mac}", f"Client-Sperre {name}")
        self._mac = mac

    @property
    def available(self) -> bool:
        return super().available and self._mac in self.coordinator.data.users

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.data.users.get(self._mac, {}).get("blocked"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        online = self.coordinator.data.clients.get(self._mac, {})
        return {"mac": self._mac, "online": bool(online),
                "network": online.get("network"), "essid": online.get("essid")}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.stamgr("block-sta", self._mac))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.stamgr("unblock-sta", self._mac))


# ------------------------------------------------------------------- Regeln
RULE_LABEL = {
    "portforwards": "Portweiterleitung",
    "trafficrules": "Traffic-Regel",
    "firewall_policies": "FW-Policy",
}


class RuleSwitch(ControllerEntity, SwitchEntity):
    _attr_icon = "mdi:shield-lock"

    def __init__(self, coordinator: UniFiCoordinator, kind: str, rule_id: str) -> None:
        rule = getattr(coordinator.data, kind)[rule_id]
        label = rule.get("name") or rule.get("description") or rule_id
        super().__init__(coordinator, f"{kind}_{rule_id}", f"{RULE_LABEL[kind]} {label}")
        self._kind = kind
        self._id = rule_id

    @property
    def _rule(self) -> dict | None:
        return getattr(self.coordinator.data, self._kind).get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._rule is not None

    @property
    def is_on(self) -> bool:
        return bool((self._rule or {}).get("enabled"))

    async def _set(self, enabled: bool) -> None:
        client = self.coordinator.client
        setter = {
            "portforwards": client.set_portforward,
            "trafficrules": client.set_trafficrule,
            "firewall_policies": client.set_firewall_policy,
        }[self._kind]
        await self.coordinator.async_command(setter(self._rule, enabled))

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)
