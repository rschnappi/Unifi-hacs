"""Zeit-Entitäten (Kinderprofile: Freigabe/Sperrzeiten)."""
from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import UniFiConfigEntry
from .kid_entities import kid_entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    for sid, ents in kid_entities(entry.runtime_data, "time").items():
        async_add_entities(ents, config_subentry_id=sid)
