"""Firmware-Updates der UniFi-Geräte als native Update-Entitäten."""
from __future__ import annotations

from typing import Any

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity, UpdateEntityFeature
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
        for mac in coordinator.data.devices:
            yield DeviceFirmwareUpdate(coordinator, mac)

    async_add_dynamic(coordinator, async_add_entities, factory)


class DeviceFirmwareUpdate(DeviceEntity, UpdateEntity):
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_supported_features = UpdateEntityFeature.INSTALL

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "firmware_update", "Firmware")

    @property
    def installed_version(self) -> str | None:
        return (self.device or {}).get("version")

    @property
    def latest_version(self) -> str | None:
        dev = self.device or {}
        if dev.get("upgradable") and dev.get("upgrade_to_firmware"):
            return dev["upgrade_to_firmware"]
        return dev.get("version")

    @property
    def in_progress(self) -> bool:
        return (self.device or {}).get("state") == 4

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        await self.coordinator.async_command(self.coordinator.client.devmgr("upgrade", self._mac))
