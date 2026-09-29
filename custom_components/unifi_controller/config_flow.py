"""Config-, Reauth- und Options-Flow. Der API-Key bleibt in secrets.yaml."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_HOST, CONF_SCAN_INTERVAL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import UniFiApiError, UniFiAuthError, UniFiClient, async_load_secret
from .const import (
    CONF_CLIENT_SWITCHES,
    CONF_FIREWALL_POLICIES,
    CONF_PORTFORWARDS,
    CONF_PREFIX,
    CONF_SECRET_NAME,
    CONF_SITE,
    CONF_TRAFFICRULES,
    DEFAULT_HOST,
    DEFAULT_PREFIX,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SECRET_NAME,
    DEFAULT_SITE,
    DOMAIN,
)


async def _validate(hass: HomeAssistant, data: Mapping[str, Any]) -> dict[str, Any]:
    """Liefert sysinfo oder wirft ValueError(<error_key>)."""
    key = await async_load_secret(hass, data[CONF_SECRET_NAME])
    if not key:
        raise ValueError("secret_not_found")
    client = UniFiClient(
        async_get_clientsession(hass, verify_ssl=data[CONF_VERIFY_SSL]),
        data[CONF_HOST], key, data[CONF_SITE],
    )
    try:
        return await client.get_sysinfo()
    except UniFiAuthError as err:
        raise ValueError("invalid_auth") from err
    except UniFiApiError as err:
        raise ValueError("cannot_connect") from err


class UniFiControllerConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(f"{user_input[CONF_HOST]}_{user_input[CONF_SITE]}")
            self._abort_if_unique_id_configured()
            try:
                await _validate(self.hass, user_input)
            except ValueError as err:
                errors["base"] = str(err)
            else:
                return self.async_create_entry(
                    title=f"UniFi {user_input[CONF_HOST]}",
                    data=user_input,
                    options={CONF_PREFIX: DEFAULT_PREFIX, CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL},
                )
        schema = vol.Schema({
            vol.Required(CONF_HOST, default=DEFAULT_HOST): str,
            vol.Required(CONF_SITE, default=DEFAULT_SITE): str,
            vol.Required(CONF_SECRET_NAME, default=DEFAULT_SECRET_NAME): str,
            vol.Required(CONF_VERIFY_SSL, default=False): bool,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, **user_input}
            try:
                await _validate(self.hass, data)
            except ValueError as err:
                errors["base"] = str(err)
            else:
                return self.async_update_reload_and_abort(entry, data_updates=user_input)
        schema = vol.Schema({
            vol.Required(CONF_SECRET_NAME, default=entry.data[CONF_SECRET_NAME]): str,
        })
        return self.async_show_form(step_id="reauth_confirm", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        return UniFiControllerOptionsFlow()


class UniFiControllerOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        o = self.config_entry.options
        schema = vol.Schema({
            vol.Required(CONF_PREFIX, default=o.get(CONF_PREFIX, DEFAULT_PREFIX)): str,
            vol.Required(
                CONF_SCAN_INTERVAL, default=o.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ): vol.All(vol.Coerce(int), vol.Range(min=10, max=600)),
            vol.Required(CONF_CLIENT_SWITCHES, default=o.get(CONF_CLIENT_SWITCHES, False)): bool,
            vol.Required(CONF_PORTFORWARDS, default=o.get(CONF_PORTFORWARDS, False)): bool,
            vol.Required(CONF_TRAFFICRULES, default=o.get(CONF_TRAFFICRULES, False)): bool,
            vol.Required(CONF_FIREWALL_POLICIES, default=o.get(CONF_FIREWALL_POLICIES, False)): bool,
        })
        return self.async_show_form(step_id="init", data_schema=schema)
