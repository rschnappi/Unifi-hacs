"""Entitäten eines Kinderprofils (Gerät „Kind <Name>“)."""
from __future__ import annotations

from datetime import datetime, time
from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.components.switch import SwitchEntity
from homeassistant.components.time import TimeEntity
from homeassistant.const import EntityCategory
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import UniFiApiError
from .const import DOMAIN
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .kids import CONF_LOCK_SCHOOL, CONF_LOCK_WEEKEND, CONF_UNLOCK, Kid


def kid_device_info(entry: UniFiConfigEntry, kid: Kid) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, f"{entry.entry_id}_kid_{kid.subentry_id}")},
        name=f"Kind {kid.name}",
        manufacturer="UniFi Controller Manager",
        model="Kinderprofil",
    )


class KidEntity(CoordinatorEntity[UniFiCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid, key: str, name: str) -> None:
        super().__init__(coordinator)
        self.kid = kid
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.entry_id}_kid_{kid.subentry_id}_{key}"
        self._attr_name = name
        self._attr_device_info = kid_device_info(entry, kid)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.kid.listeners.append(self._kid_changed)
        self.async_on_remove(lambda: self.kid.listeners.remove(self._kid_changed))

    @callback
    def _kid_changed(self) -> None:
        self.async_write_ha_state()


async def _guard(coro) -> None:
    try:
        await coro
    except UniFiApiError as err:
        raise HomeAssistantError(str(err)) from err


# ------------------------------------------------------------------ Schalter
class KidInternetSwitch(KidEntity, SwitchEntity):
    """EIN = Kind ist online (Sperr-Policies aus)."""

    _attr_icon = "mdi:web"

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid) -> None:
        super().__init__(coordinator, kid, "internet", "Internet")

    @property
    def available(self) -> bool:
        return super().available and self.kid.online is not None

    @property
    def is_on(self) -> bool | None:
        return self.kid.online

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        bonus = self.kid.bonus_until
        return {"netz": (self.kid.network or {}).get("name"),
                "bonus_bis": bonus.isoformat() if bonus else None,
                "zeitplan": self.kid.schedule}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await _guard(self.kid.async_set_online(True, "manuell"))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await _guard(self.kid.async_cancel_bonus())
        await _guard(self.kid.async_set_online(False, "manuell"))


class KidScheduleSwitch(KidEntity, SwitchEntity):
    _attr_icon = "mdi:calendar-clock"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid) -> None:
        super().__init__(coordinator, kid, "schedule", "Zeitplan")

    @property
    def is_on(self) -> bool:
        return self.kid.schedule

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.kid.async_set_schedule(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.kid.async_set_schedule(False)


# ------------------------------------------------------------------ Zeiten
TIMES = (
    (CONF_UNLOCK, "Freigabe morgens", "mdi:weather-sunset-up"),
    (CONF_LOCK_SCHOOL, "Sperre Schultag", "mdi:school"),
    (CONF_LOCK_WEEKEND, "Sperre Wochenende", "mdi:party-popper"),
)


class KidTime(KidEntity, TimeEntity):
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid, key: str, name: str,
                 icon: str) -> None:
        super().__init__(coordinator, kid, key, name)
        self._key = key
        self._attr_icon = icon

    @property
    def native_value(self) -> time:
        return self.kid.get_time(self._key)

    async def async_set_value(self, value: time) -> None:
        await self.kid.async_set_time(self._key, value)


# ------------------------------------------------------------------ Knöpfe
class KidBonusButton(KidEntity, ButtonEntity):
    _attr_icon = "mdi:timer-plus"

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid, minutes: int) -> None:
        super().__init__(coordinator, kid, f"bonus_{minutes}", f"Bonus +{minutes} min")
        self._minutes = minutes

    async def async_press(self) -> None:
        await _guard(self.kid.async_bonus(self._minutes))


# ------------------------------------------------------------------ Sensoren
class KidDevicesSensor(KidEntity, SensorEntity):
    _attr_icon = "mdi:devices"
    _attr_native_unit_of_measurement = "online"

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid) -> None:
        super().__init__(coordinator, kid, "devices", "Geräte")

    @property
    def native_value(self) -> int:
        return sum(1 for d in self.kid.devices() if d["online"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        devs = self.kid.devices()
        return {"geraete": devs, "zugeordnet": sum(1 for d in devs if d["zugeordnet"])}


class KidNextLockSensor(KidEntity, SensorEntity):
    """Nächste abendliche Sperre – mit Grund (Schultag / morgen frei: Feiertag …)."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:lock-clock"

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid) -> None:
        super().__init__(coordinator, kid, "next_lock", "Nächste Sperre")

    @property
    def native_value(self) -> datetime | None:
        return self.kid.plan.get("at") if self.kid.schedule else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self.kid.plan
        return {"art": p.get("kind"), "morgen_frei": p.get("free_tomorrow"),
                "grund": p.get("reason"), "kalender": self.kid.free_calendars,
                "kalender_gefiltert": self.kid.free_filter_calendars,
                "filter": self.kid.free_filter or None, "zeitplan": self.kid.schedule}


class KidBonusSensor(KidEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:timer-sand"

    def __init__(self, coordinator: UniFiCoordinator, kid: Kid) -> None:
        super().__init__(coordinator, kid, "bonus_until", "Bonus bis")

    @property
    def native_value(self) -> datetime | None:
        return self.kid.bonus_until


def kid_entities(coordinator: UniFiCoordinator, platform: str) -> dict[str, list]:
    """Entitäten je Kind (Subentry-ID → Liste) für eine Plattform."""
    out: dict[str, list] = {}
    manager = getattr(coordinator, "kids", None)
    for sid, kid in (manager.kids.items() if manager else []):
        if platform == "switch":
            ents = [KidInternetSwitch(coordinator, kid), KidScheduleSwitch(coordinator, kid)]
        elif platform == "time":
            ents = [KidTime(coordinator, kid, *t) for t in TIMES]
        elif platform == "button":
            ents = [KidBonusButton(coordinator, kid, 30), KidBonusButton(coordinator, kid, 60)]
        elif platform == "sensor":
            ents = [KidDevicesSensor(coordinator, kid), KidBonusSensor(coordinator, kid),
                    KidNextLockSensor(coordinator, kid)]
        else:
            ents = []
        out[sid] = ents
    return out
