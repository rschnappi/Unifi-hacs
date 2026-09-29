"""UniFi Controller Manager – Verwaltung des UniFi Network Controllers per API-Key."""
from __future__ import annotations

from homeassistant.const import CONF_HOST, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import UniFiClient, async_get_api_key
from .const import CONF_SITE, DOMAIN, PLATFORMS
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .logs import LogManager
from .services import async_setup_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


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

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def _async_reload(hass: HomeAssistant, entry: UniFiConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: UniFiConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok and entry.runtime_data.logs:
        await hass.async_add_executor_job(entry.runtime_data.logs.close)
    return ok
