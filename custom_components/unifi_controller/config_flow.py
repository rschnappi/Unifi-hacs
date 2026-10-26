"""Config-, Reconfigure-, Reauth-, Options-, Kinderprofil- und Personen-Flow."""
from __future__ import annotations

from collections.abc import Mapping
import ipaddress
import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    ConfigSubentryFlow,
    OptionsFlow,
    SubentryFlowResult,
)
from homeassistant.const import CONF_HOST, CONF_SCAN_INTERVAL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    EntitySelector,
    EntitySelectorConfig,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
    TimeSelector,
)

from .api import UniFiApiError, UniFiAuthError, UniFiClient, async_get_api_key
from .const import (
    CONF_API_KEY,
    CONF_BAN_GROUP,
    CONF_CLIENT_SWITCHES,
    CONF_FW_MANUAL,
    CONF_FW_MAX_AP,
    CONF_FW_MAX_SWITCH,
    CONF_FW_MAX_SWITCH_SITE,
    CONF_FW_SITE_PATTERN,
    DEFAULT_FW_MAX_AP,
    DEFAULT_FW_MAX_SWITCH,
    DEFAULT_FW_MAX_SWITCH_SITE,
    DEFAULT_FW_SITE_PATTERN,
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
from .kids import (
    CONF_FREE_CALENDARS,
    CONF_FREE_FILTER,
    CONF_FREE_FILTER_CALENDARS,
    CONF_LOCK_SCHOOL,
    CONF_LOCK_WEEKEND,
    CONF_NAME as KID_NAME,
    CONF_NETWORK as KID_NETWORK,
    CONF_SCHEDULE as KID_SCHEDULE,
    CONF_UNLOCK,
    DEFAULT_LOCK_SCHOOL,
    DEFAULT_LOCK_WEEKEND,
    DEFAULT_UNLOCK,
    SUBENTRY_KID,
    async_create_network,
    kid_zone,
)
from .presence import (
    CONF_AWAY_DELAY,
    CONF_DEVICES as PERSON_DEVICES,
    CONF_EXIT_APS,
    CONF_EXIT_DELAY,
    CONF_NAME as PERSON_NAME,
    CONF_SOURCES,
    DEFAULT_AWAY_DELAY,
    DEFAULT_EXIT_DELAY,
    SUBENTRY_PERSON,
    ap_options,
    device_options,
)
from .notifications import NOTIFY_CATEGORIES, PERSISTENT as PERSISTENT_TARGET, notify_targets, option_key
from .region import (
    async_apply,
    async_country_codes,
    state as region_state,
    target_zones,
    zone_id,
    zone_of_network,
)
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


def dt_now_iso() -> str:
    from homeassistant.util import dt as dt_util  # noqa: PLC0415

    return dt_util.now().isoformat(timespec="seconds")


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

    @classmethod
    @callback
    def async_get_supported_subentry_types(
        cls, config_entry: ConfigEntry
    ) -> dict[str, type[ConfigSubentryFlow]]:
        from .s2s import SUBENTRY_S2S  # noqa: PLC0415

        return {SUBENTRY_KID: KidSubentryFlow, SUBENTRY_PERSON: PersonSubentryFlow,
                SUBENTRY_S2S: SiteToSiteSubentryFlow}


NEW_NETWORK = "__new__"


class KidSubentryFlow(ConfigSubentryFlow):
    """Kinderprofil anlegen / ändern. Löschen über das Menü des Eintrags."""

    def _coordinator(self):
        return getattr(self._get_entry(), "runtime_data", None)

    def _used_networks(self, except_id: str | None = None) -> set[str]:
        return {s.data.get(KID_NETWORK) for sid, s in self._get_entry().subentries.items()
                if s.subentry_type == SUBENTRY_KID and sid != except_id}

    def _schema(self, d: dict[str, Any], networks: dict[str, str] | None) -> vol.Schema:
        fields: dict[Any, Any] = {vol.Required(KID_NAME, default=d.get(KID_NAME, "")): str}
        if networks is not None:
            fields[vol.Required(KID_NETWORK, default=d.get(KID_NETWORK, NEW_NETWORK))] = \
                SelectSelector(SelectSelectorConfig(
                    options=[SelectOptionDict(value=k, label=v) for k, v in networks.items()],
                    mode=SelectSelectorMode.DROPDOWN))
        fields.update({
            vol.Required(CONF_UNLOCK, default=d.get(CONF_UNLOCK, DEFAULT_UNLOCK)): TimeSelector(),
            vol.Required(CONF_LOCK_SCHOOL,
                         default=d.get(CONF_LOCK_SCHOOL, DEFAULT_LOCK_SCHOOL)): TimeSelector(),
            vol.Required(CONF_LOCK_WEEKEND,
                         default=d.get(CONF_LOCK_WEEKEND, DEFAULT_LOCK_WEEKEND)): TimeSelector(),
            vol.Required(KID_SCHEDULE, default=d.get(KID_SCHEDULE, True)): bool,
            vol.Optional(CONF_FREE_CALENDARS,
                         default=d.get(CONF_FREE_CALENDARS, self._default_calendars())):
                EntitySelector(EntitySelectorConfig(domain="calendar", multiple=True)),
            vol.Optional(CONF_FREE_FILTER_CALENDARS,
                         default=d.get(CONF_FREE_FILTER_CALENDARS, [])):
                EntitySelector(EntitySelectorConfig(domain="calendar", multiple=True)),
            vol.Optional(CONF_FREE_FILTER, default=d.get(CONF_FREE_FILTER, d.get(KID_NAME, ""))): str,
        })
        return vol.Schema(fields)

    def _default_calendars(self) -> list[str]:
        """Vorschlag: Feiertagskalender, falls vorhanden."""
        return [s.entity_id for s in self.hass.states.async_all("calendar")
                if "feiertag" in s.entity_id or "holiday" in s.entity_id][:1]

    def _network_options(self) -> dict[str, str]:
        c = self._coordinator()
        used = self._used_networks()
        data = c.data if c else None
        zone = kid_zone(data) if data else None
        nets = {nid: n.get("name", nid) for nid, n in (data.config.get("networks", {}) if data else {}).items()
                if n.get("purpose") == "corporate" and nid not in used
                and (not zone or zone_of_network(data, n) == zone)}
        return {NEW_NETWORK: "➕ Neues Netz anlegen (VLAN + Subnetz automatisch)", **nets}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        c = self._coordinator()
        if c is None or c.data is None:
            return self.async_abort(reason="not_loaded")
        errors: dict[str, str] = {}
        if user_input is not None:
            name = user_input[KID_NAME].strip()
            names = {s.title.lower() for s in self._get_entry().subentries.values()
                     if s.subentry_type == SUBENTRY_KID}
            if not name:
                errors[KID_NAME] = "name_required"
            elif name.lower() in names:
                errors[KID_NAME] = "name_exists"
            else:
                net_id = user_input[KID_NETWORK]
                try:
                    if net_id == NEW_NETWORK:
                        net_id = await async_create_network(c, name)
                except UniFiApiError:
                    errors["base"] = "network_failed"
                else:
                    import time as _t  # noqa: PLC0415
                    data = {**user_input, KID_NAME: name, KID_NETWORK: net_id, "rev": _t.time()}
                    return self.async_create_entry(title=name, data=data, unique_id=net_id)
        return self.async_show_form(
            step_id="user", data_schema=self._schema(user_input or {}, self._network_options()),
            errors=errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        sub = self._get_reconfigure_subentry()
        errors: dict[str, str] = {}
        if user_input is not None:
            name = user_input[KID_NAME].strip()
            others = {s.title.lower() for sid, s in self._get_entry().subentries.items()
                      if s.subentry_type == SUBENTRY_KID and sid != sub.subentry_id}
            if not name:
                errors[KID_NAME] = "name_required"
            elif name.lower() in others:
                errors[KID_NAME] = "name_exists"
            else:
                import time as _t  # noqa: PLC0415
                return self.async_update_and_abort(
                    self._get_entry(), sub, title=name,
                    data={**sub.data, **user_input, KID_NAME: name, "rev": _t.time()})
        current = dict(sub.data)
        c = self._coordinator()
        if c and c.kids and (kid := c.kids.kids.get(sub.subentry_id)):
            current.update({k: kid.get_time(k).isoformat() for k in
                            (CONF_UNLOCK, CONF_LOCK_SCHOOL, CONF_LOCK_WEEKEND)},
                           **{KID_SCHEDULE: kid.schedule,
                              CONF_FREE_CALENDARS: kid.free_calendars,
                              CONF_FREE_FILTER_CALENDARS: kid.free_filter_calendars,
                              CONF_FREE_FILTER: kid.free_filter})
        return self.async_show_form(
            step_id="reconfigure", data_schema=self._schema(user_input or current, None),
            errors=errors)


class PersonSubentryFlow(ConfigSubentryFlow):
    """Person für die Anwesenheitserkennung anlegen / ändern."""

    def _coordinator(self):
        return getattr(self._get_entry(), "runtime_data", None)

    def _names(self, except_id: str | None = None) -> set[str]:
        return {s.title.lower() for sid, s in self._get_entry().subentries.items()
                if s.subentry_type == SUBENTRY_PERSON and sid != except_id}

    def _schema(self, d: dict[str, Any]) -> vol.Schema:
        c = self._coordinator()
        devs = device_options(c)
        known = {m for m, _ in devs}
        # bereits gewählte, dem Controller (noch) unbekannte MACs nicht verlieren
        devs += [(m, f"{m} – unbekannt") for m in d.get(PERSON_DEVICES, []) if m not in known]
        aps = ap_options(c)
        return vol.Schema({
            vol.Required(PERSON_NAME, default=d.get(PERSON_NAME, "")): str,
            vol.Required(PERSON_DEVICES, default=d.get(PERSON_DEVICES, [])): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=m, label=lbl) for m, lbl in devs],
                    multiple=True, mode=SelectSelectorMode.DROPDOWN, sort=False)),
            vol.Optional(CONF_EXIT_APS, default=d.get(CONF_EXIT_APS, [])): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=m, label=n) for m, n in aps],
                    multiple=True, mode=SelectSelectorMode.LIST)),
            vol.Required(CONF_EXIT_DELAY, default=d.get(CONF_EXIT_DELAY, DEFAULT_EXIT_DELAY)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=120)),
            vol.Required(CONF_AWAY_DELAY, default=d.get(CONF_AWAY_DELAY, DEFAULT_AWAY_DELAY)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=240)),
            vol.Optional(CONF_SOURCES, default=d.get(CONF_SOURCES, [])): EntitySelector(
                EntitySelectorConfig(domain=["device_tracker", "binary_sensor"], multiple=True)),
        })

    def _check(self, user_input: dict[str, Any], except_id: str | None) -> dict[str, str]:
        errors: dict[str, str] = {}
        name = user_input[PERSON_NAME].strip()
        own = [e for e in user_input.get(CONF_SOURCES, [])
               if e.startswith("device_tracker.") and self._is_own_tracker(e)]
        if not name:
            errors[PERSON_NAME] = "name_required"
        elif name.lower() in self._names(except_id):
            errors[PERSON_NAME] = "person_exists"
        elif not user_input.get(PERSON_DEVICES) and not user_input.get(CONF_SOURCES):
            errors["base"] = "no_devices"
        elif own:
            errors[CONF_SOURCES] = "own_tracker"
        elif user_input[CONF_EXIT_DELAY] > user_input[CONF_AWAY_DELAY]:
            errors[CONF_EXIT_DELAY] = "exit_longer"
        return errors

    def _is_own_tracker(self, entity_id: str) -> bool:
        """Eigene Tracker als Zusatzquelle würden sich selbst bestätigen."""
        from homeassistant.helpers import entity_registry as er  # noqa: PLC0415

        ent = er.async_get(self.hass).async_get(entity_id)
        return bool(ent and ent.config_entry_id == self._get_entry().entry_id)

    @staticmethod
    def _data(user_input: dict[str, Any]) -> dict[str, Any]:
        return {**user_input, PERSON_NAME: user_input[PERSON_NAME].strip(),
                PERSON_DEVICES: [m.lower() for m in user_input.get(PERSON_DEVICES, [])]}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        c = self._coordinator()
        if c is None or c.data is None:
            return self.async_abort(reason="not_loaded")
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = self._check(user_input, None)
            if not errors:
                data = self._data(user_input)
                return self.async_create_entry(title=data[PERSON_NAME], data=data)
        return self.async_show_form(
            step_id="user", data_schema=self._schema(user_input or {}), errors=errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        c = self._coordinator()
        if c is None or c.data is None:
            return self.async_abort(reason="not_loaded")
        sub = self._get_reconfigure_subentry()
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = self._check(user_input, sub.subentry_id)
            if not errors:
                data = self._data(user_input)
                return self.async_update_and_abort(
                    self._get_entry(), sub, title=data[PERSON_NAME], data=data)
        return self.async_show_form(
            step_id="reconfigure", data_schema=self._schema(user_input or dict(sub.data)),
            errors=errors)


class SiteToSiteSubentryFlow(ConfigSubentryFlow):
    """Assistent: Site-to-Site-Tunnel zu einer Firmen-Firewall (Sophos XGS, XFRM).

    1. Gegenstelle und Firmennetze · 2. Heimseite (VLAN/Subnetze) · 3. Vorschau (Dry-Run) und
    Anlegen in UniFi + Anleitung für die Sophos.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._reconf = False

    def _coordinator(self):
        return getattr(self._get_entry(), "runtime_data", None)

    def _step1_schema(self, d: dict[str, Any]) -> vol.Schema:
        from homeassistant.helpers.selector import (  # noqa: PLC0415
            TextSelector,
            TextSelectorConfig,
        )

        multi = TextSelector(TextSelectorConfig(multiline=True))
        c = self._coordinator()

        def txt(key: str) -> str:
            v = d.get(key)
            return ", ".join(v) if isinstance(v, list) else (v or "")
        return vol.Schema({
            vol.Required("firma", default=d.get("firma", "Firma")): str,
            vol.Required("peer_fqdn", default=d.get("peer_fqdn", "")): str,
            vol.Required("local_id", default=d.get("local_id") or (
                c.vpn_endpoint if c else "") or ""): str,
            vol.Required("remote_nets", default=txt("remote_nets")): multi,
            vol.Required("remote_dns", default=txt("remote_dns")): str,
            vol.Optional("radius_servers", description={"suggested_value": txt("radius_servers")}):
                str,
            vol.Optional("ssid", description={"suggested_value": d.get("ssid") or ""}): str,
            vol.Required("full_tunnel", default=d.get("full_tunnel", True)): bool,
            vol.Required("allow_support", default=d.get("allow_support", True)): bool,
        })

    @staticmethod
    def _step2_schema(d: dict[str, Any]) -> vol.Schema:
        from .s2s import DEFAULTS  # noqa: PLC0415

        g = DEFAULTS | {k: v for k, v in d.items() if v not in (None, "")}
        return vol.Schema({
            vol.Required("preferred_vlan", default=int(g["preferred_vlan"])):
                vol.All(vol.Coerce(int), vol.Range(min=2, max=4009)),
            vol.Required("preferred_subnet", default=g["preferred_subnet"]): str,
            vol.Required("subnet_pool", default=g["subnet_pool"]): str,
            vol.Required("transfer_pool", default=g["transfer_pool"]): str,
            **{vol.Optional(k, description={"suggested_value": g.get(k) or ""}): str
               for k in ("group_name", "zone_name", "net_name", "radius_name", "tunnel_name")},
        })

    async def _start(self, data: dict[str, Any]) -> SubentryFlowResult:
        c = self._coordinator()
        if c is None or c.data is None:
            return self.async_abort(reason="not_loaded")
        self._data = dict(data)
        return await self._step1(None)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        return await self._start({})

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        self._reconf = True
        return await self._start(dict(self._get_reconfigure_subentry().data))

    async def _step1(self, user_input: dict[str, Any] | None) -> SubentryFlowResult:
        return await self.async_step_tunnel(user_input)

    async def async_step_tunnel(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        from .s2s import SUBENTRY_S2S, normalize, validate_input  # noqa: PLC0415

        errors: dict[str, str] = {}
        if user_input is not None:
            user_input.setdefault("radius_servers", "")
            user_input.setdefault("ssid", "")
            errors = validate_input(user_input)
            firma = user_input.get("firma", "").strip().lower()
            other = {s.data.get("firma", "").lower() for sid, s in
                     self._get_entry().subentries.items() if s.subentry_type == SUBENTRY_S2S
                     and not (self._reconf and sid == self._get_reconfigure_subentry().subentry_id)}
            if firma in other:
                errors["firma"] = "s2s_exists"
            if not errors:
                self._data |= normalize(user_input)
                if self._data.get("radius_servers") and not self._data.get("ssid"):
                    self._data["ssid"] = None
                return await self.async_step_home()
        return self.async_show_form(
            step_id="tunnel", data_schema=self._step1_schema(user_input or self._data),
            errors=errors)

    async def async_step_home(self, user_input: dict[str, Any] | None = None) -> SubentryFlowResult:
        from .s2s import validate_input  # noqa: PLC0415

        errors: dict[str, str] = {}
        if user_input is not None:
            errors = {k: v for k, v in validate_input({**self._data, **user_input}).items()
                      if k in user_input}
            if not errors:
                for k in ("group_name", "zone_name", "net_name", "radius_name", "tunnel_name"):
                    user_input[k] = (user_input.get(k) or "").strip()
                self._data |= user_input
                return await self.async_step_confirm()
        return self.async_show_form(
            step_id="home", data_schema=self._step2_schema(user_input or self._data),
            errors=errors)

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        from .s2s import S2SConfig, S2SError, async_publish, async_run  # noqa: PLC0415

        c = self._coordinator()
        cfg = S2SConfig.from_dict(self._data)
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                report = await async_run(c, cfg, apply=user_input["apply"],
                                         backup=user_input["backup"],
                                         rename=user_input.get("rename", False))
                await async_publish(c, cfg, report)
            except S2SError as err:
                errors["base"] = "s2s_failed"
                self._error = str(err)
            except UniFiApiError as err:
                errors["base"] = "s2s_failed"
                self._error = str(err)
            else:
                data = {**self._data, "last_run": dt_now_iso(),
                        "applied": bool(user_input["apply"])}
                title = f"{cfg.firma} → {cfg.peer_fqdn}"
                if self._reconf:
                    return self.async_update_and_abort(
                        self._get_entry(), self._get_reconfigure_subentry(), title=title,
                        data=data)
                return self.async_create_entry(title=title, data=data)
        try:
            preview = (await async_run(c, cfg, apply=False, rename=True)).markdown()
        except (S2SError, UniFiApiError) as err:
            preview = f"⛔ {err}"
            errors.setdefault("base", "s2s_blocked")
        if errors.get("base") == "s2s_failed":
            preview = f"⛔ {getattr(self, '_error', '')}\n\n{preview}"
        schema = vol.Schema({
            vol.Required("apply", default=True): bool,
            vol.Required("backup", default=True): bool,
            vol.Required("rename", default=False): bool,
        })
        return self.async_show_form(step_id="confirm", data_schema=schema, errors=errors,
                                    description_placeholders={"plan": preview})


class UniFiControllerOptionsFlow(OptionsFlow):
    _net_id: str = ""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return self.async_show_menu(
            step_id="init", menu_options=["general", "networks", "logs", "region", "notify", "firmware"])

    async def async_step_notify(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Empfänger je Benachrichtigungs-Kategorie."""
        if user_input is not None:
            return self.async_create_entry(data={**self.config_entry.options, **user_input})
        o = self.config_entry.options
        targets = notify_targets(self.hass)
        options = [SelectOptionDict(value=k, label=v) for k, v in targets.items()]
        schema = vol.Schema({
            vol.Optional(option_key(cat), default=[t for t in o.get(option_key(cat), [PERSISTENT_TARGET])
                                                   if t in targets]):
                SelectSelector(SelectSelectorConfig(options=options, multiple=True,
                                                    mode=SelectSelectorMode.LIST))
            for cat in NOTIFY_CATEGORIES
        })
        return self.async_show_form(step_id="notify", data_schema=schema)

    async def async_step_firmware(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Geräte, die nie automatisch/als Sammel-Update aktualisiert werden."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                re.compile(user_input.get(CONF_FW_SITE_PATTERN) or DEFAULT_FW_SITE_PATTERN)
            except re.error:
                errors[CONF_FW_SITE_PATTERN] = "invalid_pattern"
            else:
                return self.async_create_entry(data={**self.config_entry.options, **user_input})
        o = self.config_entry.options
        coordinator = getattr(self.config_entry, "runtime_data", None)
        devices = coordinator.data.devices if coordinator and coordinator.data else {}
        labels = {
            mac.lower(): f"{d.get('name') or mac} ({d.get('model') or d.get('type') or '?'})"
            for mac, d in devices.items()
        }
        current = [m for m in self.config_entry.options.get(CONF_FW_MANUAL, [])]
        for m in current:
            labels.setdefault(m, m)
        schema = vol.Schema({
            vol.Optional(CONF_FW_MANUAL, default=current): SelectSelector(
                SelectSelectorConfig(
                    options=[SelectOptionDict(value=k, label=v)
                             for k, v in sorted(labels.items(), key=lambda i: i[1].lower())],
                    multiple=True, mode=SelectSelectorMode.LIST)),
            vol.Required(CONF_FW_MAX_AP, default=o.get(CONF_FW_MAX_AP, DEFAULT_FW_MAX_AP)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
            vol.Required(CONF_FW_MAX_SWITCH,
                         default=o.get(CONF_FW_MAX_SWITCH, DEFAULT_FW_MAX_SWITCH)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
            vol.Required(CONF_FW_MAX_SWITCH_SITE,
                         default=o.get(CONF_FW_MAX_SWITCH_SITE, DEFAULT_FW_MAX_SWITCH_SITE)):
                vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
            vol.Required(CONF_FW_SITE_PATTERN,
                         default=o.get(CONF_FW_SITE_PATTERN, DEFAULT_FW_SITE_PATTERN)): str,
        })
        return self.async_show_form(step_id="firmware", data_schema=schema, errors=errors)

    async def async_step_networks(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Netze: zuerst das Netz wählen."""
        from .netconfig import gateway_networks  # noqa: PLC0415

        coordinator = getattr(self.config_entry, "runtime_data", None)
        nets = gateway_networks(coordinator) if coordinator else {}
        if not nets:
            return self.async_abort(reason="networks_unsupported")
        if user_input is not None:
            self._net_id = user_input["network"]
            return await self.async_step_network_edit()
        schema = vol.Schema({
            vol.Required("network"): SelectSelector(SelectSelectorConfig(
                options=[SelectOptionDict(value=k, label=v) for k, v in nets.items()],
                mode=SelectSelectorMode.LIST)),
        })
        return self.async_show_form(step_id="networks", data_schema=schema)

    async def async_step_network_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Netz bearbeiten: Grundeinstellungen, Subnetz und DHCP."""
        from .netconfig import (  # noqa: PLC0415
            NetworkConfigError,
            async_read,
            async_set_network,
            flatten,
        )

        coordinator = self.config_entry.runtime_data
        errors: dict[str, str] = {}
        try:
            current = flatten(await async_read(coordinator, self._net_id))
        except NetworkConfigError:
            return self.async_abort(reason="networks_unsupported")
        except UniFiApiError:
            return self.async_abort(reason="cannot_connect")
        if user_input is not None:
            confirm = user_input.pop("confirm_subnet_change", False)
            if not user_input.get("domain_name"):
                user_input["domain_name"] = ""
            try:
                await async_set_network(coordinator, self._net_id, user_input, confirm)
            except NetworkConfigError as err:
                errors["base"] = err.key
            except UniFiApiError:
                errors["base"] = "network_failed"
            else:
                return self.async_create_entry(data=dict(self.config_entry.options))
            current |= {k: v for k, v in user_input.items() if v is not None}
        dhcp = current.get("dhcp_mode") in (None, "SERVER")
        fields: dict[Any, Any] = {
            vol.Required("name", default=current.get("name") or ""): str,
            vol.Required("enabled", default=bool(current.get("enabled"))): bool,
        }
        if current.get("vlan") not in (None, 1):
            fields[vol.Required("vlan", default=current["vlan"])] = vol.All(
                vol.Coerce(int), vol.Range(min=2, max=4009))
        for key in ("internet_access", "isolation", "mdns", "cellular_backup"):
            if current.get(key) is not None:
                fields[vol.Required(key, default=bool(current[key]))] = bool
        if current.get("gateway_ip"):
            fields[vol.Required("gateway_ip", default=current["gateway_ip"])] = str
            fields[vol.Required("prefix_length", default=current.get("prefix_length") or 24)] = \
                vol.All(vol.Coerce(int), vol.Range(min=8, max=30))
        if dhcp and current.get("dhcp_start"):
            fields[vol.Required("dhcp_start", default=current["dhcp_start"])] = str
            fields[vol.Required("dhcp_stop", default=current.get("dhcp_stop") or "")] = str
            fields[vol.Required("lease_time", default=current.get("lease_time") or 86400)] = \
                vol.All(vol.Coerce(int), vol.Range(min=60, max=31536000))
            fields[vol.Optional("domain_name",
                                description={"suggested_value": current.get("domain_name")})] = str
            if current.get("ping_conflict_detection") is not None:
                fields[vol.Required("ping_conflict_detection",
                                    default=bool(current["ping_conflict_detection"]))] = bool
        if current.get("gateway_ip"):
            fields[vol.Required("confirm_subnet_change", default=False)] = bool
        return self.async_show_form(
            step_id="network_edit", data_schema=vol.Schema(fields), errors=errors,
            description_placeholders={"network": current.get("name") or "",
                                      "dhcp_mode": current.get("dhcp_mode") or "–"})

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
