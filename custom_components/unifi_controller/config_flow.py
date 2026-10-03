"""Config-, Reconfigure-, Reauth- und Options-Flow."""
from __future__ import annotations

from collections.abc import Mapping
import ipaddress
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_HOST, CONF_SCAN_INTERVAL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import UniFiApiError, UniFiAuthError, UniFiClient, async_get_api_key
from .const import (
    CONF_API_KEY,
    CONF_BAN_GROUP,
    CONF_CLIENT_SWITCHES,
    CONF_CONFIG_INTERVAL,
    CONF_F2B,
    CONF_F2B_BANTIME,
    CONF_F2B_BANTIME_INSTANT,
    CONF_F2B_CATEGORIES,
    CONF_F2B_FINDTIME,
    CONF_F2B_HA_LOGIN,
    CONF_F2B_INSTANT,
    CONF_F2B_MAXRETRY,
    CONF_F2B_RECIDIVE,
    CONF_F2B_WHITELIST,
    CONF_KID_NETWORKS,
    CONF_LOG_BACKFILL,
    CONF_LOG_FILE,
    CONF_LOGS,
    CONF_NEW_CLIENT_NOTIFY,
    CONF_PREFIX,
    CONF_SECRET_NAME,
    CONF_SITE,
    CONF_SWITCH_GROUPS,
    CONF_VPN_ENDPOINT,
    DEFAULT_BAN_GROUP,
    DEFAULT_CONFIG_INTERVAL,
    DEFAULT_F2B_BANTIME,
    DEFAULT_F2B_BANTIME_INSTANT,
    DEFAULT_F2B_CATEGORIES,
    DEFAULT_F2B_FINDTIME,
    DEFAULT_F2B_INSTANT,
    DEFAULT_F2B_MAXRETRY,
    DEFAULT_F2B_RECIDIVE,
    DEFAULT_HOST,
    DEFAULT_PREFIX,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
    DOMAIN,
)
from .flows import default_kid_networks
from .region import async_apply, async_country_codes, state as region_state, target_zones, zone_id
from .resources import SWITCH_GROUP_KEYS, SWITCH_GROUPS

GROUP_LABELS = {
    "wlans": "WLANs",
    "networks": "Netzwerke/VLANs (aktiv)",
    "networks_internet": "Netzwerke/VLANs (Internetzugang)",
    "vpn": "VPN-Server/-Clients",
    "firewall_policies": "Firewall-Policies (eigene)",
    "trafficrules": "Traffic-Regeln",
    "trafficroutes": "Traffic-Routen",
    "portforwards": "Portweiterleitungen",
    "qos_rules": "QoS-Regeln",
    "routes": "Statische Routen",
    "dns_records": "DNS-Einträge",
}
PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def _conn_schema(d: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema({
        vol.Required(CONF_HOST, default=d.get(CONF_HOST, DEFAULT_HOST)): str,
        vol.Required(CONF_SITE, default=d.get(CONF_SITE, DEFAULT_SITE)): str,
        vol.Optional(CONF_API_KEY): PASSWORD,
        vol.Optional(CONF_SECRET_NAME, default=d.get(CONF_SECRET_NAME, "")): str,
        vol.Required(CONF_VERIFY_SSL, default=d.get(CONF_VERIFY_SSL, False)): bool,
    })


def _clean(data: Mapping[str, Any]) -> dict[str, Any]:
    out = {k: (v.strip() if isinstance(v, str) else v) for k, v in data.items()}
    out.setdefault(CONF_API_KEY, "")
    out.setdefault(CONF_SECRET_NAME, "")
    return out


async def _validate(hass: HomeAssistant, data: Mapping[str, Any]) -> dict[str, Any]:
    """Liefert sysinfo oder wirft ValueError(<error_key>)."""
    if not data.get(CONF_API_KEY) and not data.get(CONF_SECRET_NAME):
        raise ValueError("no_key")
    key = await async_get_api_key(hass, data)
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
            data = _clean(user_input)
            await self.async_set_unique_id(f"{data[CONF_HOST]}_{data[CONF_SITE]}")
            self._abort_if_unique_id_configured()
            try:
                await _validate(self.hass, data)
            except ValueError as err:
                errors["base"] = str(err)
            else:
                return self.async_create_entry(
                    title=f"UniFi {data[CONF_HOST]}",
                    data=data,
                    options={CONF_PREFIX: DEFAULT_PREFIX, CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL},
                )
        return self.async_show_form(
            step_id="user", data_schema=_conn_schema(user_input or {}), errors=errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Host, Site, API-Key usw. nachträglich ändern."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = _clean(user_input)
            if not data[CONF_API_KEY] and not data[CONF_SECRET_NAME]:
                data[CONF_API_KEY] = entry.data.get(CONF_API_KEY, "")  # leer = Key behalten
            try:
                await _validate(self.hass, data)
            except ValueError as err:
                errors["base"] = str(err)
            else:
                return self.async_update_reload_and_abort(
                    entry,
                    unique_id=f"{data[CONF_HOST]}_{data[CONF_SITE]}",
                    title=f"UniFi {data[CONF_HOST]}",
                    data={**entry.data, **data},
                )
        return self.async_show_form(
            step_id="reconfigure", data_schema=_conn_schema(entry.data), errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, **_clean(user_input)}
            try:
                await _validate(self.hass, data)
            except ValueError as err:
                errors["base"] = str(err)
            else:
                return self.async_update_reload_and_abort(entry, data=data)
        schema = vol.Schema({
            vol.Optional(CONF_API_KEY): PASSWORD,
            vol.Optional(CONF_SECRET_NAME, default=entry.data.get(CONF_SECRET_NAME, "")): str,
        })
        return self.async_show_form(step_id="reauth_confirm", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        return UniFiControllerOptionsFlow()


class UniFiControllerOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return self.async_show_menu(step_id="init", menu_options=["general", "logs", "region"])

    async def async_step_region(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Länder-Blocking über Zonen-Policies – wird direkt im Controller gespeichert."""
        coordinator = getattr(self.config_entry, "runtime_data", None)
        data = coordinator.data if coordinator else None
        if data is None or not zone_id(data, "external"):
            return self.async_abort(reason="region_unsupported")
        errors: dict[str, str] = {}
        try:
            codes = await async_country_codes(coordinator)
        except UniFiApiError:
            return self.async_abort(reason="region_unsupported")
        zones = target_zones(data)
        if user_input is not None:
            exceptions = [e.strip() for e in user_input.get("region_exceptions", "").split(",")
                          if e.strip()]
            try:
                for e in exceptions:
                    ipaddress.ip_network(e, strict=False)
            except ValueError:
                errors["region_exceptions"] = "invalid_network"
            if not user_input.get("region_countries"):
                errors["base"] = "no_countries"
            if not errors:
                try:
                    await async_apply(
                        coordinator,
                        enabled=user_input["region_enabled"],
                        countries=user_input["region_countries"],
                        exceptions=exceptions,
                        zones=user_input.get("region_zones", []),
                        wireguard=user_input["region_wireguard"],
                    )
                except UniFiApiError:
                    errors["base"] = "region_failed"
                else:
                    return self.async_create_entry(data=dict(self.config_entry.options))
        st = region_state(data)
        default_zones = st["zones"] or [z for z, n in zones.items() if n.lower() == "iot"]
        schema = vol.Schema({
            vol.Required("region_enabled", default=st["enabled"]): bool,
            vol.Required("region_countries", default=st["countries"] or ["AT"]): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=c, label=f"{n} ({c})")
                             for c, n in sorted(codes.items(), key=lambda i: i[1])],
                    multiple=True, mode=SelectSelectorMode.DROPDOWN, sort=False)),
            vol.Required("region_zones", default=default_zones): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=z, label=n) for z, n in zones.items()],
                    multiple=True, mode=SelectSelectorMode.LIST)),
            vol.Required("region_wireguard", default=st["wireguard"]): bool,
            vol.Optional("region_exceptions", default=", ".join(st["exceptions"])): str,
        })
        return self.async_show_form(step_id="region", data_schema=schema, errors=errors)

    async def async_step_general(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data={**self.config_entry.options, **user_input})
        o = self.config_entry.options
        coordinator = getattr(self.config_entry, "runtime_data", None)
        data = coordinator.data if coordinator else None
        nets = {
            nid: n.get("name", nid)
            for nid, n in (data.config.get("networks", {}) if data else {}).items()
            if n.get("purpose") in ("corporate", "guest")
        }
        kid_default = [n for n in o.get(CONF_KID_NETWORKS) or (
            default_kid_networks(coordinator) if coordinator else []) if n in nets]
        schema = vol.Schema({
            vol.Required(CONF_PREFIX, default=o.get(CONF_PREFIX, DEFAULT_PREFIX)): str,
            vol.Required(
                CONF_SCAN_INTERVAL, default=o.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ): vol.All(vol.Coerce(int), vol.Range(min=10, max=600)),
            vol.Required(
                CONF_CONFIG_INTERVAL, default=o.get(CONF_CONFIG_INTERVAL, DEFAULT_CONFIG_INTERVAL)
            ): vol.All(vol.Coerce(int), vol.Range(min=30, max=3600)),
            vol.Required(
                CONF_SWITCH_GROUPS, default=o.get(CONF_SWITCH_GROUPS, SWITCH_GROUP_KEYS)
            ): cv.multi_select({g.key: GROUP_LABELS.get(g.key, g.key) for g in SWITCH_GROUPS}),
            vol.Required(CONF_CLIENT_SWITCHES, default=o.get(CONF_CLIENT_SWITCHES, False)): bool,
            vol.Required(CONF_NEW_CLIENT_NOTIFY,
                         default=o.get(CONF_NEW_CLIENT_NOTIFY, True)): bool,
            vol.Optional(CONF_KID_NETWORKS, default=kid_default): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=k, label=v) for k, v in nets.items()],
                    multiple=True, mode=SelectSelectorMode.LIST)),
            vol.Optional(CONF_VPN_ENDPOINT, default=o.get(CONF_VPN_ENDPOINT, "")): str,
        })
        return self.async_show_form(step_id="general", data_schema=schema)

    async def async_step_logs(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data={**self.config_entry.options, **user_input})
        o = self.config_entry.options
        schema = vol.Schema({
            vol.Required(CONF_LOGS, default=o.get(CONF_LOGS, True)): bool,
            vol.Optional(CONF_LOG_FILE, default=o.get(CONF_LOG_FILE, "")): str,
            vol.Required(CONF_LOG_BACKFILL, default=o.get(CONF_LOG_BACKFILL, 0)):
                vol.All(vol.Coerce(int), vol.Range(min=0, max=1440)),
            vol.Required(CONF_F2B, default=o.get(CONF_F2B, False)): bool,
            vol.Required(CONF_F2B_MAXRETRY, default=o.get(CONF_F2B_MAXRETRY, DEFAULT_F2B_MAXRETRY)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=1000)),
            vol.Required(CONF_F2B_FINDTIME, default=o.get(CONF_F2B_FINDTIME, DEFAULT_F2B_FINDTIME)):
                vol.All(vol.Coerce(int), vol.Range(min=10, max=86400)),
            vol.Required(CONF_F2B_BANTIME, default=o.get(CONF_F2B_BANTIME, DEFAULT_F2B_BANTIME)):
                vol.All(vol.Coerce(int), vol.Range(min=0, max=525600)),
            vol.Required(CONF_F2B_BANTIME_INSTANT,
                         default=o.get(CONF_F2B_BANTIME_INSTANT, DEFAULT_F2B_BANTIME_INSTANT)):
                vol.All(vol.Coerce(int), vol.Range(min=0, max=525600)),
            vol.Required(CONF_F2B_RECIDIVE, default=o.get(CONF_F2B_RECIDIVE, DEFAULT_F2B_RECIDIVE)):
                vol.All(vol.Coerce(int), vol.Range(min=0, max=100)),
            vol.Required(
                CONF_F2B_CATEGORIES, default=o.get(CONF_F2B_CATEGORIES, DEFAULT_F2B_CATEGORIES)
            ): str,
            vol.Required(
                CONF_F2B_INSTANT, default=o.get(CONF_F2B_INSTANT, DEFAULT_F2B_INSTANT)
            ): str,
            vol.Required(CONF_F2B_HA_LOGIN, default=o.get(CONF_F2B_HA_LOGIN, True)): bool,
            vol.Optional(CONF_F2B_WHITELIST, default=o.get(CONF_F2B_WHITELIST, "")): str,
            vol.Required(CONF_BAN_GROUP, default=o.get(CONF_BAN_GROUP, DEFAULT_BAN_GROUP)): str,
        })
        return self.async_show_form(step_id="logs", data_schema=schema)
