"""Text-Entitäten: Eingabefelder des DNS-Formulars (Domain, Ziel)."""
from __future__ import annotations

from homeassistant.components.text import TextEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .entity import ControllerEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    c = entry.runtime_data
    async_add_entities([DnsText(c, "domain", "DNS Domain", "mdi:web"),
                        DnsText(c, "value", "DNS Ziel", "mdi:target")])


class DnsText(ControllerEntity, TextEntity):
    """Feld des DNS-Formulars – Wert lebt im gemeinsamen Formular-Zustand."""

    _attr_native_max = 255

    def __init__(self, coordinator: UniFiCoordinator, field: str, name: str, icon: str) -> None:
        super().__init__(coordinator, f"dns_form_{field}", name)
        self._field = field
        self._attr_icon = icon

    @callback
    def async_entity_id_changed(self, old_entity_id: str) -> None:
        """HA 2026.11+: Entity-ID direkt umbenennen statt entfernen/neu anlegen."""
        if parent := getattr(super(), "async_entity_id_changed", None):
            parent(old_entity_id)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.dns_form.async_add_listener(self.async_write_ha_state))

    @property
    def native_value(self) -> str:
        return getattr(self.coordinator.dns_form, self._field)

    async def async_set_value(self, value: str) -> None:
        self.coordinator.dns_form.set(**{self._field: value.strip()})
