"""UniFi Controller Manager – Verwaltung des UniFi Network Controllers per API-Key."""
from __future__ import annotations

import logging

from homeassistant.const import CONF_HOST, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import UniFiClient, async_get_api_key
from .const import CONF_SITE, DOMAIN, PLATFORMS
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .kids import KidManager
from .logs import LogManager
from .resources import SWITCH_GROUPS, switch_suffix
from .services import async_setup_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: UniFiConfigEntry) -> bool:
    api_key = await async_get_api_key(hass, entry.data)
    if not api_key:
        raise ConfigEntryAuthFailed("Kein API-Key konfiguriert bzw. in secrets.yaml gefunden")
    client = UniFiClient(
        async_get_clientsession(hass, verify_ssl=entry.data[CONF_VERIFY_SSL]),
        entry.data[CONF_HOST],
        api_key,
        entry.data[CONF_SITE],
    )
    coordinator = UniFiCoordinator(hass, entry, client)
    coordinator.logs = LogManager(hass, coordinator)
    await coordinator.logs.async_setup()
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    _async_migrate_unique_ids(hass, entry, coordinator)
    coordinator.kids = KidManager(hass, coordinator)
    await coordinator.kids.async_setup()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


def _async_migrate_unique_ids(
    hass: HomeAssistant, entry: UniFiConfigEntry, coordinator: UniFiCoordinator
) -> None:
    """Regel-Schalter von UniFi-ID auf namensbasierte Unique-ID umstellen (einmalig).

    Entity-IDs, Verlauf und Automationen bleiben erhalten – nur die interne Unique-ID
    wechselt, damit ein Schalter das Löschen + Neuanlegen seiner Regel übersteht.
    """
    registry = er.async_get(hass)
    base = f"{entry.entry_id}_"
    mapping: dict[str, str] = {}
    for group in SWITCH_GROUPS:
        if not group.by_name:
            continue
        for obj_id, obj in coordinator.data.config.get(group.dataset, {}).items():
            old = f"{base}{group.uid_prefix}_{obj_id}"
            mapping[old] = f"{base}{switch_suffix(group, obj_id, obj)}"
    if not mapping:
        return
    taken = {
        e.unique_id for e in er.async_entries_for_config_entry(registry, entry.entry_id)
    }
    for ent in er.async_entries_for_config_entry(registry, entry.entry_id):
        new = mapping.get(ent.unique_id)
        if ent.domain != "switch" or not new or new == ent.unique_id:
            continue
        if new in taken:          # Ziel existiert schon (z. B. gleichnamige Regel)
            continue
        registry.async_update_entity(ent.entity_id, new_unique_id=new)
        taken.add(new)
        _LOGGER.debug("Unique-ID migriert: %s → %s", ent.entity_id, new)


async def _async_reload(hass: HomeAssistant, entry: UniFiConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: UniFiConfigEntry) -> bool:
    if entry.runtime_data.kids:
        entry.runtime_data.kids.async_unload()
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok and entry.runtime_data.logs:
        await hass.async_add_executor_job(entry.runtime_data.logs.close)
    return ok
