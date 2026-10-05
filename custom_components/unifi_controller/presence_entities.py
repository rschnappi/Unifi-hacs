"""Entitäten einer Person (Gerät „Person <Name>“) + device_tracker je Gerät."""
from __future__ import annotations

import time
from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .presence import Person


def person_device_info(entry: UniFiConfigEntry, person: Person) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, f"{entry.entry_id}_person_{person.subentry_id}")},
        name=f"Person {person.name}",
        manufacturer="UniFi Controller Manager",
        model="Anwesenheit",
    )


class PersonEntity(CoordinatorEntity[UniFiCoordinator]):
    """Basis: aktualisiert bei Abruf, Log-Event und Zustandsänderung der Zusatzquellen."""

    def __init__(self, coordinator: UniFiCoordinator, person: Person) -> None:
        super().__init__(coordinator)
        self.person = person

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.person.listeners.append(self._person_changed)
        self.async_on_remove(lambda: self.person.listeners.remove(self._person_changed))

    @callback
    def _person_changed(self) -> None:
        self.async_write_ha_state()


class PersonDeviceEntity(PersonEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: UniFiCoordinator, person: Person, key: str,
                 name: str) -> None:
        super().__init__(coordinator, person)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.entry_id}_person_{person.subentry_id}_{key}"
        self._attr_name = name
        self._attr_device_info = person_device_info(entry, person)


class PersonPresence(PersonDeviceEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.PRESENCE

    def __init__(self, coordinator: UniFiCoordinator, person: Person) -> None:
        super().__init__(coordinator, person, "presence", "Anwesend")

    @property
    def is_on(self) -> bool | None:
        return self.person.present

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self.person
        return {
            "seit": p.since.isoformat() if p.since else None,
            "grund": p.reason,
            "ausloeser": p.trigger,
            "geraete": p.device_attrs(time.time()),
            "zusatzquellen": p.source_states(),
            "frist_ausgang_min": p.exit_delay // 60,
            "frist_haus_min": p.away_delay // 60,
            "ausgangs_aps": [p.manager.uplink_name(m) for m in sorted(p.exit_aps)],
        }


class PersonRoom(PersonDeviceEntity, SensorEntity):
    _attr_icon = "mdi:home-map-marker"

    def __init__(self, coordinator: UniFiCoordinator, person: Person) -> None:
        super().__init__(coordinator, person, "room", "Raum")

    @property
    def native_value(self) -> str:
        return self.person.room()


class PersonDeviceTracker(PersonEntity, ScannerEntity):
    """Router-Tracker eines Geräts – mit denselben entprellten Fristen wie die Person."""

    _attr_has_entity_name = False
    _attr_entity_category = None

    def __init__(self, coordinator: UniFiCoordinator, person: Person, mac: str) -> None:
        super().__init__(coordinator, person)
        self._mac = mac
        self._uid = f"{coordinator.config_entry.entry_id}_person_{person.subentry_id}_{mac}"
        ds = person.manager.devices.get(mac)
        self._attr_mac_address = mac
        self._attr_name = f"{person.name} {ds.name if ds and ds.name else mac}"
        self._attr_icon = "mdi:cellphone-wireless"
        self._sync()

    @property
    def unique_id(self) -> str:
        return self._uid

    @property
    def entity_registry_enabled_default(self) -> bool:
        return True       # ausdrücklich gewählt – nicht vom HA-Geräte-Abgleich abhängig

    @property
    def _ds(self):
        return self.person.manager.devices.get(self._mac)

    def _sync(self) -> None:
        ds = self._ds
        if ds is None:
            return
        if ds.ip != self._attr_ip_address:
            self._attr_ip_address = ds.ip
        if ds.hostname != self._attr_hostname:
            self._attr_hostname = ds.hostname

    @callback
    def _person_changed(self) -> None:
        self._sync()
        super()._person_changed()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._sync()
        super()._handle_coordinator_update()

    @property
    def is_connected(self) -> bool:
        return self.person.device_present(self._mac, time.time())[0]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ds = self._ds
        if ds is None:
            return {}
        m = self.person.manager
        return {
            "verbunden": ds.connected,
            "grund": self.person.device_present(self._mac, time.time())[1],
            "ap": m.uplink_name(ds.uplink) if ds.uplink else None,
            "raum": m.uplink_room(ds.uplink) if ds.connected and ds.uplink else None,
            "ssid": ds.ssid, "signal": ds.signal, "kabel": ds.wired,
            "zuletzt": dt_util.utc_from_timestamp(ds.last_seen).isoformat()
            if ds.last_seen else None,
        }


def presence_entities(coordinator: UniFiCoordinator, platform: str) -> dict[str, list]:
    """Entitäten je Person (Subentry-ID → Liste) für eine Plattform."""
    out: dict[str, list] = {}
    manager = getattr(coordinator, "presence", None)
    for sid, person in (manager.persons.items() if manager else []):
        if platform == "binary_sensor":
            ents = [PersonPresence(coordinator, person)]
        elif platform == "sensor":
            ents = [PersonRoom(coordinator, person)]
        elif platform == "device_tracker":
            ents = [PersonDeviceTracker(coordinator, person, mac) for mac in person.macs]
        else:
            ents = []
        out[sid] = ents
    return out
