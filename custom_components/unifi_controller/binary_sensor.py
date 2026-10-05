"""Binärsensoren: Gerät online, Update verfügbar, Internet, WAN1/WAN2, Fail2Ban aktiv, Anwesenheit."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic
from .presence_entities import presence_entities

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
        for mac, dev in coordinator.data.devices.items():
            yield DeviceOnline(coordinator, mac)
            yield DeviceUpgradable(coordinator, mac)
            for key in ("wan1", "wan2"):
                if dev.get(key):
                    yield WanOnline(coordinator, mac, key)

    async_add_dynamic(coordinator, async_add_entities, factory)
    for sid, ents in presence_entities(coordinator, "binary_sensor").items():
        async_add_entities(ents, config_subentry_id=sid)


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
            "bantime_instant_min": logs.bantime_instant, "recidive": logs.recidive,
            "categories": sorted(logs.categories), "instant_events": sorted(logs.instant),
            "ha_login": logs.ha_login, "group": logs.group_name,
            "whitelist": [str(n) for n in logs.whitelist], "log_error": logs.last_error,
        }


class WanOnline(DeviceEntity, BinarySensorEntity):
    """WAN-Leitung hat Link + Verfügbarkeit laut UniFi-Monitoren."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: UniFiCoordinator, mac: str, key: str) -> None:
        super().__init__(coordinator, mac, f"{key}_online", key.upper())
        self._key = key

    @property
    def _wan(self) -> dict:
        return (self.device or {}).get(self._key) or {}

    @property
    def is_on(self) -> bool:
        return bool(self._wan.get("up"))

    @property
    def extra_state_attributes(self) -> dict:
        dev = self.device or {}
        stats = (dev.get("uptime_stats") or {}).get("WAN" if self._key == "wan1" else "WAN2") or {}
        w = self._wan
        return {"ip": w.get("ip"), "port": w.get("name"), "medium": w.get("media"),
                "speed": w.get("speed"), "latenz_ms": w.get("latency"),
                "verfuegbarkeit": stats.get("availability"),
                "uptime_s": stats.get("uptime"), "downtime_s": stats.get("downtime")}
