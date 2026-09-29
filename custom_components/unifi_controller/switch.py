"""Schalter: alle Config-Objekte (WLAN, Netze, VPN, FW …), Länder-Blocking, Geräte, Clients."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import UniFiApiError
from .const import CONF_CLIENT_SWITCHES, CONF_SWITCH_GROUPS
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic
from .region import async_apply, country_names, state as region_state, zone_id
from .resources import SWITCH_GROUP_KEYS, SWITCH_GROUPS, SwitchGroup, object_name


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    opts = entry.options
    groups = [g for g in SWITCH_GROUPS if g.key in opts.get(CONF_SWITCH_GROUPS, SWITCH_GROUP_KEYS)]

    def factory():
        data = coordinator.data
        for group in groups:
            for obj_id, obj in data.config.get(group.dataset, {}).items():
                if group.field in obj and group.filter(obj):
                    yield ResourceSwitch(coordinator, group, obj_id)
        if zone_id(data, "external") and region_state(data)["zones"]:
            yield RegionSwitch(coordinator)
        for mac, dev in data.devices.items():
            if "led_override" in dev or dev.get("type") in ("uap", "usw"):
                yield LedSwitch(coordinator, mac)
            yield LocateSwitch(coordinator, mac)
            for port in dev.get("port_table", []):
                if port.get("port_poe"):
                    yield PoeSwitch(coordinator, mac, port["port_idx"])
        if opts.get(CONF_CLIENT_SWITCHES):
            for mac, user in data.users.items():
                if user.get("name"):
                    yield ClientBlockSwitch(coordinator, mac)

    async_add_dynamic(coordinator, async_add_entities, factory)


# ------------------------------------------------------------ Config-Objekte
class ResourceSwitch(ControllerEntity, SwitchEntity):
    """Schaltet ein Boolean-Feld (meist 'enabled') eines Config-Objekts."""

    def __init__(self, coordinator: UniFiCoordinator, group: SwitchGroup, obj_id: str) -> None:
        obj = coordinator.data.config[group.dataset][obj_id]
        super().__init__(
            coordinator, f"{group.uid_prefix}_{obj_id}",
            f"{group.label} {object_name(obj)}{group.suffix}",
        )
        self._group = group
        self._id = obj_id
        self._attr_icon = group.icon

    @property
    def _obj(self) -> dict | None:
        return self.coordinator.data.config.get(self._group.dataset, {}).get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._obj is not None

    @property
    def is_on(self) -> bool:
        return bool((self._obj or {}).get(self._group.field))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        obj = self._obj
        return self._group.attrs(obj, self.coordinator.data.config) if obj else {}

    async def _set(self, value: bool) -> None:
        try:
            await self.coordinator.async_update_object(
                self._group.dataset, self._obj, {self._group.field: value}
            )
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)


# ------------------------------------------------------------ Länder-Blocking
class RegionSwitch(ControllerEntity, SwitchEntity):
    """Schaltet die „Rest blocken“-Policies des Länder-Blockings (Allow-Regeln bleiben)."""

    _attr_icon = "mdi:earth-off"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "region_blocking", "Länder-Blocking")

    @property
    def is_on(self) -> bool:
        return region_state(self.coordinator.data)["enabled"]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        st = region_state(self.coordinator.data)
        return {**st, "names": country_names(st["countries"])}

    async def _set(self, value: bool) -> None:
        try:
            await async_apply(self.coordinator, enabled=value)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err

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
