"""Basisklassen und Helfer für Entitäten."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_PREFIX, DEFAULT_PREFIX, DOMAIN, MANUFACTURER
from .coordinator import UniFiConfigEntry, UniFiCoordinator

DEVICE_TYPES = {
    "uap": "Access Point",
    "usw": "Switch",
    "ugw": "Gateway",
    "udm": "Gateway",
    "uxg": "Gateway",
}


def prefix(entry: UniFiConfigEntry) -> str:
    return entry.options.get(CONF_PREFIX, DEFAULT_PREFIX).strip()


def controller_device_info(entry: UniFiConfigEntry, coordinator: UniFiCoordinator) -> DeviceInfo:
    sysinfo = coordinator.data.sysinfo if coordinator.data else {}
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name=f"{prefix(entry)} UniFi".strip(),
        manufacturer=MANUFACTURER,
        model="UniFi Network Controller",
        sw_version=sysinfo.get("version"),
        configuration_url=f"https://{coordinator.client.host}",
    )


def network_device_info(entry: UniFiConfigEntry, device: dict) -> DeviceInfo:
    # Kein via_device: ab HA 2026.x deprecated (Entfernung 2027.8)
    mac = device["mac"].lower()
    name = device.get("name") or device.get("model") or mac
    return DeviceInfo(
        identifiers={(DOMAIN, f"{entry.entry_id}_{mac}")},
        name=f"{prefix(entry)} {name}".strip(),
        manufacturer=MANUFACTURER,
        model=device.get("model"),
        sw_version=device.get("version"),
    )


class UniFiEntity(CoordinatorEntity[UniFiCoordinator]):
    """Gemeinsame Basis."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: UniFiCoordinator, unique_suffix: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}_{unique_suffix}"


class ControllerEntity(UniFiEntity):
    """Entität am Controller-Gerät."""

    def __init__(self, coordinator: UniFiCoordinator, unique_suffix: str, name: str) -> None:
        super().__init__(coordinator, unique_suffix)
        self._attr_name = name
        self._attr_device_info = controller_device_info(coordinator.config_entry, coordinator)


class DeviceEntity(UniFiEntity):
    """Entität an einem UniFi-Gerät (AP/Switch/Gateway)."""

    def __init__(self, coordinator: UniFiCoordinator, mac: str, key: str, name: str) -> None:
        super().__init__(coordinator, f"{mac}_{key}")
        self._mac = mac
        self._attr_name = name
        self._attr_device_info = network_device_info(
            coordinator.config_entry, coordinator.data.devices[mac]
        )

    @property
    def device(self) -> dict | None:
        return self.coordinator.data.devices.get(self._mac)

    @property
    def available(self) -> bool:
        return super().available and self.device is not None


@callback
def async_add_dynamic(
    coordinator: UniFiCoordinator,
    add_entities: Callable[[Iterable[Entity]], None],
    factory: Callable[[], Iterable[UniFiEntity]],
) -> None:
    """Entitäten anlegen und bei neuen Objekten (Gerät, WLAN, Regel…) nachziehen."""
    known: set[str] = set()

    @callback
    def _check() -> None:
        if not coordinator.data:
            return
        new = [e for e in factory() if e.unique_id not in known]
        if new:
            known.update(e.unique_id for e in new)
            add_entities(new)

    _check()
    coordinator.config_entry.async_on_unload(coordinator.async_add_listener(_check))
