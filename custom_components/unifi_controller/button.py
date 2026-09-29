"""Buttons: Geräteneustart, PoE Power-Cycle, Schlüssel/Passwörter neu erzeugen."""
from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import UniFiApiError
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic
from .resources import object_name
from .secrets_mgmt import async_rotate_wireguard, async_rotate_wlan, is_wireguard


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        for net_id, net in coordinator.data.config.get("networks", {}).items():
            if is_wireguard(net):
                yield RotateWireguardButton(coordinator, net_id)
        for wlan_id in coordinator.data.config.get("wlans", {}):
            yield RotateWlanButton(coordinator, wlan_id)
        for mac, dev in coordinator.data.devices.items():
            yield RestartButton(coordinator, mac)
            for port in dev.get("port_table", []):
                if port.get("port_poe"):
                    yield PowerCycleButton(coordinator, mac, port["port_idx"])

    async_add_dynamic(coordinator, async_add_entities, factory)


class RestartButton(DeviceEntity, ButtonEntity):
    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "restart", "Neustart")

    async def async_press(self) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("restart", self._mac))


class PowerCycleButton(DeviceEntity, ButtonEntity):
    _attr_icon = "mdi:power-cycle"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, mac: str, port_idx: int) -> None:
        super().__init__(coordinator, mac, f"power_cycle_{port_idx}", f"Port {port_idx} Power-Cycle")
        self._idx = port_idx

    async def async_press(self) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("power-cycle", self._mac, port_idx=self._idx))


class RotateWireguardButton(ControllerEntity, ButtonEntity):
    """Neuen WireGuard-Serverschlüssel erzeugen (Clients brauchen neue Configs)."""

    _attr_icon = "mdi:key-change"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, net_id: str) -> None:
        net = coordinator.data.config["networks"][net_id]
        super().__init__(coordinator, f"rotate_wg_{net_id}",
                         f"VPN {object_name(net)} Schlüssel neu erzeugen")
        self._id = net_id

    async def async_press(self) -> None:
        net = self.coordinator.data.config.get("networks", {}).get(self._id)
        if not net:
            raise HomeAssistantError("VPN nicht mehr vorhanden")
        try:
            await async_rotate_wireguard(self.coordinator, net)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err


class RotateWlanButton(ControllerEntity, ButtonEntity):
    """Neues WLAN-Passwort (Anzeige als Benachrichtigung). Standardmäßig deaktiviert."""

    _attr_icon = "mdi:form-textbox-password"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, wlan_id: str) -> None:
        wlan = coordinator.data.config["wlans"][wlan_id]
        super().__init__(coordinator, f"rotate_wlan_{wlan_id}",
                         f"WLAN {object_name(wlan)} Passwort neu erzeugen")
        self._id = wlan_id

    async def async_press(self) -> None:
        wlan = self.coordinator.data.config.get("wlans", {}).get(self._id)
        if not wlan:
            raise HomeAssistantError("WLAN nicht mehr vorhanden")
        try:
            await async_rotate_wlan(self.coordinator, wlan, 24, notify=True)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err
