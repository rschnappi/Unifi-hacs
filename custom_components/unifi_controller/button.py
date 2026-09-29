"""Buttons: Geräteneustart und PoE Power-Cycle."""
from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import DeviceEntity, async_add_dynamic


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
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
