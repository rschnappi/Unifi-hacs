"""device_tracker: Geräte der Personen (Anwesenheit mit entprellten Fristen)."""
from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry
from .presence_entities import presence_entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    for sid, ents in presence_entities(entry.runtime_data, "device_tracker").items():
        async_add_entities(ents, config_subentry_id=sid)
