"""Sensoren: Controller-Health, WAN, Client-Zähler, Geräte-Stats."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfDataRate,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .coordinator import UniFiConfigEntry, UniFiCoordinator, UniFiData
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic


@dataclass(frozen=True, kw_only=True)
class ControllerSensorDescription(SensorEntityDescription):
    value_fn: Callable[[UniFiData], Any]


@dataclass(frozen=True, kw_only=True)
class DeviceSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict], Any]
    exists_fn: Callable[[dict], bool] = lambda d: True


def _wan(d: UniFiData) -> dict:
    return d.health.get("wan", {})


def _uptime(seconds: Any) -> datetime | None:
    if not seconds:
        return None
    ts = dt_util.utcnow() - timedelta(seconds=int(seconds))
    return ts.replace(second=0, microsecond=0)  # verhindert Zustandsflattern


RATE = dict(
    device_class=SensorDeviceClass.DATA_RATE,
    native_unit_of_measurement=UnitOfDataRate.BYTES_PER_SECOND,
    suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
    state_class=SensorStateClass.MEASUREMENT,
)

CONTROLLER_SENSORS: tuple[ControllerSensorDescription, ...] = (
    ControllerSensorDescription(
        key="wan_ip", name="WAN IP", icon="mdi:ip-network",
        value_fn=lambda d: _wan(d).get("wan_ip"),
    ),
    ControllerSensorDescription(
        key="wan_rx", name="WAN Download", **RATE,
        value_fn=lambda d: _wan(d).get("rx_bytes-r"),
    ),
    ControllerSensorDescription(
        key="wan_tx", name="WAN Upload", **RATE,
        value_fn=lambda d: _wan(d).get("tx_bytes-r"),
    ),
    ControllerSensorDescription(
        key="wan_latency", name="WAN Latenz", native_unit_of_measurement="ms",
        state_class=SensorStateClass.MEASUREMENT, icon="mdi:timer-outline",
        value_fn=lambda d: d.health.get("www", {}).get("latency"),
    ),
    ControllerSensorDescription(
        key="clients_total", name="Clients online", icon="mdi:devices",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: len(d.clients),
    ),
    ControllerSensorDescription(
        key="clients_wireless", name="Clients WLAN", icon="mdi:wifi",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: sum(1 for c in d.clients.values() if not c.get("is_wired")),
    ),
    ControllerSensorDescription(
        key="clients_wired", name="Clients LAN", icon="mdi:ethernet",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: sum(1 for c in d.clients.values() if c.get("is_wired")),
    ),
    ControllerSensorDescription(
        key="clients_guest", name="Clients Gäste", icon="mdi:account-question",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: sum(1 for c in d.clients.values() if c.get("is_guest")),
    ),
    ControllerSensorDescription(
        key="devices_total", name="Geräte adoptiert", icon="mdi:access-point-network",
        state_class=SensorStateClass.MEASUREMENT, entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: len(d.devices),
    ),
    ControllerSensorDescription(
        key="version", name="Network Version", icon="mdi:tag",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.sysinfo.get("version"),
    ),
)

DEVICE_SENSORS: tuple[DeviceSensorDescription, ...] = (
    DeviceSensorDescription(
        key="cpu", name="CPU", native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT, icon="mdi:cpu-64-bit",
        exists_fn=lambda d: "cpu" in (d.get("system-stats") or {}),
        value_fn=lambda d: _float((d.get("system-stats") or {}).get("cpu")),
    ),
    DeviceSensorDescription(
        key="mem", name="Speicher", native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT, icon="mdi:memory",
        exists_fn=lambda d: "mem" in (d.get("system-stats") or {}),
        value_fn=lambda d: _float((d.get("system-stats") or {}).get("mem")),
    ),
    DeviceSensorDescription(
        key="temperature", name="Temperatur",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        exists_fn=lambda d: "general_temperature" in d,
        value_fn=lambda d: d.get("general_temperature"),
    ),
    DeviceSensorDescription(
        key="clients", name="Clients", icon="mdi:devices",
        state_class=SensorStateClass.MEASUREMENT,
        exists_fn=lambda d: "num_sta" in d,
        value_fn=lambda d: d.get("num_sta"),
    ),
    DeviceSensorDescription(
        key="rx", name="Durchsatz RX", **RATE,
        exists_fn=lambda d: "rx_bytes-r" in d,
        value_fn=lambda d: d.get("rx_bytes-r"),
    ),
    DeviceSensorDescription(
        key="tx", name="Durchsatz TX", **RATE,
        exists_fn=lambda d: "tx_bytes-r" in d,
        value_fn=lambda d: d.get("tx_bytes-r"),
    ),
    DeviceSensorDescription(
        key="uptime", name="Gestartet", device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: _uptime(d.get("uptime")),
    ),
    DeviceSensorDescription(
        key="firmware", name="Firmware", icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.get("version"),
    ),
    DeviceSensorDescription(
        key="ip", name="IP", icon="mdi:ip",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.get("ip"),
    ),
)


def _float(value: Any) -> float | None:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        data = coordinator.data
        for desc in CONTROLLER_SENSORS:
            yield ControllerSensor(coordinator, desc)
        for sub in data.health:
            yield HealthSensor(coordinator, sub)
        for mac, dev in data.devices.items():
            for desc in DEVICE_SENSORS:
                if desc.exists_fn(dev):
                    yield DeviceSensor(coordinator, mac, desc)

    async_add_dynamic(coordinator, async_add_entities, factory)


class ControllerSensor(ControllerEntity, SensorEntity):
    entity_description: ControllerSensorDescription

    def __init__(self, coordinator: UniFiCoordinator, desc: ControllerSensorDescription) -> None:
        super().__init__(coordinator, f"ctrl_{desc.key}", desc.name)
        self.entity_description = desc

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)


class HealthSensor(ControllerEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["ok", "warning", "error", "unknown"]
    _attr_icon = "mdi:heart-pulse"

    def __init__(self, coordinator: UniFiCoordinator, subsystem: str) -> None:
        super().__init__(coordinator, f"health_{subsystem}", f"Status {subsystem.upper()}")
        self._sub = subsystem

    @property
    def native_value(self) -> str | None:
        status = self.coordinator.data.health.get(self._sub, {}).get("status")
        return status if status in self._attr_options else "unknown"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        raw = self.coordinator.data.health.get(self._sub, {})
        # nur Zähler – Raten würden den Recorder aufblähen
        return {k: v for k, v in raw.items() if k.startswith("num_")}


class DeviceSensor(DeviceEntity, SensorEntity):
    entity_description: DeviceSensorDescription

    def __init__(self, coordinator: UniFiCoordinator, mac: str, desc: DeviceSensorDescription) -> None:
        super().__init__(coordinator, mac, desc.key, desc.name)
        self.entity_description = desc

    @property
    def native_value(self) -> Any:
        dev = self.device
        return self.entity_description.value_fn(dev) if dev else None
