"""Event-Entitäten: UniFi System-Log und Fail2Ban-Aktionen."""
from __future__ import annotations

from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import EVENT_BAN
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity
from .logs import EVENT_TYPES, event_type


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[EventEntity] = [Fail2BanEvent(coordinator)]
    if coordinator.logs and coordinator.logs.enabled:
        entities.append(LogEvent(coordinator))
    async_add_entities(entities)


class LogEvent(ControllerEntity, EventEntity):
    """Jeder neue System-Log-Eintrag (Typ = Kategorie)."""

    _attr_event_types = EVENT_TYPES
    _attr_icon = "mdi:text-box-search"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "log_event", "Log")

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.logs.async_add_listener(self._handle))

    @callback
    def _handle(self, entry: dict[str, Any]) -> None:
        attrs = {k: v for k, v in entry.items() if v is not None and k != "id"}
        self._trigger_event(event_type(entry.get("category")), attrs)
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Zustand nur bei Log-Einträgen ändern, nicht bei jedem Poll."""


class Fail2BanEvent(ControllerEntity, EventEntity):
    _attr_event_types = ["ban", "unban"]
    _attr_icon = "mdi:shield-alert"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "fail2ban_event", "Fail2Ban")

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.hass.bus.async_listen(EVENT_BAN, self._handle))

    @callback
    def _handle(self, event: Event) -> None:
        data = dict(event.data)
        self._trigger_event(data.pop("action", "ban"), data)
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Nur auf Ban-Events reagieren."""
