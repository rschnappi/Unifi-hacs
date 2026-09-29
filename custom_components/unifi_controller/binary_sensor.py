"""Binärsensoren: Gerät online, Update verfügbar, Internet, Fail2Ban aktiv."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic

# UniFi-Gerätestatus: 1 verbunden, 4 Update läuft, 5 provisioniert gerade – alles „online“
ONLINE_STATES = {1, 4, 5}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        yield InternetSensor(coordinator)
        if coordinator.logs:
            yield Fail2BanActive(coordinator)
        for mac in coordinator.data.devices:
            yield DeviceOnline(coordinator, mac)
            yield DeviceUpgradable(coordinator, mac)

    async_add_dynamic(coordinator, async_add_entities, factory)


class InternetSensor(ControllerEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "ctrl_internet", "Internet")

    @property
    def is_on(self) -> bool | None:
        www = self.coordinator.data.health.get("www")
        return None if www is None else www.get("status") == "ok"


class DeviceOnline(DeviceEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "online", "Online")

    @property
    def is_on(self) -> bool:
        return (self.device or {}).get("state") in ONLINE_STATES


class DeviceUpgradable(DeviceEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.UPDATE
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "upgradable", "Firmware-Update")

    @property
    def is_on(self) -> bool:
        return bool((self.device or {}).get("upgradable"))


class Fail2BanActive(ControllerEntity, BinarySensorEntity):
    _attr_icon = "mdi:shield-check"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "fail2ban_active", "Fail2Ban aktiv")

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.logs.f2b)

    @property
    def extra_state_attributes(self) -> dict:
        logs = self.coordinator.logs
        return {
            "maxretry": logs.maxretry, "findtime_s": logs.findtime, "bantime_min": logs.bantime,
            "categories": sorted(logs.categories), "instant_events": sorted(logs.instant),
            "ha_login": logs.ha_login, "group": logs.group_name,
            "whitelist": [str(n) for n in logs.whitelist], "log_error": logs.last_error,
        }
