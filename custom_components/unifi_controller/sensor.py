"""Sensoren: Controller, WAN, Clients, Netzwerke, Logs, Fail2Ban, Länder-Blocking, Geräte."""
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
from .region import country_names, geo_setting, geo_state
from .resources import LAN_PURPOSES, VPN_PURPOSES, object_name, scalar_attrs

STAT_SENSORS = (
    ("events", "Log-Einträge heute", "mdi:text-box-multiple"),
    ("security", "Security-Events heute", "mdi:shield-alert-outline"),
    ("threats", "IPS-Angriffe heute", "mdi:shield-bug"),
    ("fw_blocks", "Firewall-Blocks heute", "mdi:wall-fire"),
    ("ha_login", "HA-Login-Fehlversuche heute", "mdi:account-alert"),
    ("bans", "Fail2Ban-Sperren heute", "mdi:shield-lock"),
)


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

DEVICE_STATES = {
    0: "offline", 1: "verbunden", 2: "adoption_ausstehend", 4: "update", 5: "provisionierung",
    6: "heartbeat_fehlt", 7: "adoption", 9: "adoptionsfehler", 10: "adoption_fehlgeschlagen",
    11: "isoliert",
}

DEVICE_SENSORS: tuple[DeviceSensorDescription, ...] = (
    DeviceSensorDescription(
        key="status", name="Status", icon="mdi:access-point-check",
        device_class=SensorDeviceClass.ENUM,
        options=[*DEVICE_STATES.values(), "unbekannt"],
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: DEVICE_STATES.get(d.get("state"), "unbekannt"),
    ),
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
        for net_id, net in data.config.get("networks", {}).items():
            if net.get("purpose") in LAN_PURPOSES | VPN_PURPOSES:
                yield NetworkClientsSensor(coordinator, net_id)
        yield BanSensor(coordinator)
        if coordinator.logs and coordinator.logs.enabled:
            for key, name, icon in STAT_SENSORS:
                yield StatSensor(coordinator, key, name, icon)
            yield LastAlertSensor(coordinator)
            yield LastBanSensor(coordinator)
        if geo_setting(data) is not None:
            yield RegionSensor(coordinator)
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


class NetworkClientsSensor(ControllerEntity, SensorEntity):
    """Clients je Netzwerk/VLAN; Netz-Konfiguration als Attribute."""

    _attr_icon = "mdi:lan-connect"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: UniFiCoordinator, net_id: str) -> None:
        net = coordinator.data.config["networks"][net_id]
        label = "VPN" if net.get("purpose") in VPN_PURPOSES else "Netzwerk"
        super().__init__(
            coordinator, f"network_clients_{net_id}", f"{label} {object_name(net)} Clients"
        )
        self._id = net_id

    @property
    def _net(self) -> dict | None:
        return self.coordinator.data.config.get("networks", {}).get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._net is not None

    @property
    def native_value(self) -> int:
        name = (self._net or {}).get("name")
        return sum(
            1 for c in self.coordinator.data.clients.values()
            if c.get("network_id") == self._id or (name and c.get("network") == name)
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        net = self._net or {}
        keep = ("purpose", "vlan", "vlan_enabled", "ip_subnet", "enabled", "dhcpd_enabled",
                "dhcpd_start", "dhcpd_stop", "internet_access_enabled",
                "network_isolation_enabled", "vpn_type", "local_port", "id")
        attrs = scalar_attrs(net)
        return {k: attrs[k] for k in keep if k in attrs}


class BanSensor(ControllerEntity, SensorEntity):
    """Anzahl aktuell per Fail2Ban gesperrter IPs (Liste als Attribut)."""

    _attr_icon = "mdi:shield-lock"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "IPs"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "fail2ban_bans", "Fail2Ban gesperrt")

    @property
    def native_value(self) -> int:
        logs = self.coordinator.logs
        return len(logs.bans) if logs else 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        logs = self.coordinator.logs
        if not logs:
            return {}
        return {
            "bans": logs.ban_list(),
            "enabled": logs.f2b,
            "group": logs.group_name,
            "maxretry": logs.maxretry,
            "findtime_s": logs.findtime,
            "bantime_min": logs.bantime,
            "log_error": logs.last_error,
        }


class StatSensor(ControllerEntity, SensorEntity):
    """Tageszähler aus dem System-Log (Reset um Mitternacht)."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = "Ereignisse"

    def __init__(self, coordinator: UniFiCoordinator, key: str, name: str, icon: str) -> None:
        super().__init__(coordinator, f"stat_{key}", name)
        self._key = key
        self._attr_icon = icon

    @property
    def native_value(self) -> int:
        return self.coordinator.logs.stat(self._key)


class LastAlertSensor(ControllerEntity, SensorEntity):
    """Letzte sicherheitsrelevante Meldung im Klartext."""

    _attr_icon = "mdi:alert-decagram"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "last_alert", "Letzte Sicherheitsmeldung")

    @property
    def native_value(self) -> str | None:
        a = self.coordinator.logs.last_alert
        if not a:
            return "keine"
        return (a.get("message") or a.get("event") or "")[:255]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return dict(self.coordinator.logs.last_alert or {})


class LastBanSensor(ControllerEntity, SensorEntity):
    _attr_icon = "mdi:shield-account"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "last_ban", "Fail2Ban letzte Sperre")

    @property
    def native_value(self) -> str:
        b = self.coordinator.logs.last_ban
        return f"{b['ip']} – {b['reason']}"[:255] if b else "keine"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return dict(self.coordinator.logs.last_ban or {})


class RegionSensor(ControllerEntity, SensorEntity):
    """Anzahl der Länder im Länder-Blocking, Liste als Attribut."""

    _attr_icon = "mdi:earth-off"
    _attr_native_unit_of_measurement = "Länder"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "region_countries", "Länder-Blocking Länder")

    @property
    def native_value(self) -> int:
        return len(geo_state(geo_setting(self.coordinator.data))["countries"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        st = geo_state(geo_setting(self.coordinator.data))
        return {**st, "names": country_names(st["countries"])}
