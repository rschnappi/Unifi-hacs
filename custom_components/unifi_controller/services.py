"""Services: CRUD, Logs/Fail2Ban, Länder-Blocking, Flows, VPN-Zugänge, Betrieb, App-Sperren, Aktionen."""
from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .api import UniFiApiError
from .const import DOMAIN
from .coordinator import UniFiCoordinator
from .flows import APP_DOMAINS, async_query
from .logs import parse_entry
from .region import async_apply, country_names
from .resources import DATASETS, object_name, redact
from .secrets_mgmt import async_rotate_wireguard, async_rotate_wlan

_LOGGER = logging.getLogger(__name__)

ATTR_ENTRY = "config_entry_id"
ATTR_MAC = "mac"
ATTR_RESOURCE = "resource"
ATTR_OBJECT = "object"

BASE = {vol.Optional(ATTR_ENTRY): cv.string}
MAC_SCHEMA = vol.Schema({**BASE, vol.Required(ATTR_MAC): cv.string})
RESOURCE = vol.In(list(DATASETS))


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as err:
        raise vol.Invalid(f"Keine gültige IP: {value}") from err


def _coordinator(hass: HomeAssistant, call: ServiceCall) -> UniFiCoordinator:
    entries = [
        e for e in hass.config_entries.async_entries(DOMAIN)
        if e.state is ConfigEntryState.LOADED
    ]
    if entry_id := call.data.get(ATTR_ENTRY):
        entries = [e for e in entries if e.entry_id == entry_id]
    if len(entries) != 1:
        raise ServiceValidationError(
            "Genau ein geladener UniFi-Controller erforderlich – config_entry_id angeben"
        )
    return entries[0].runtime_data


async def _run(coro) -> Any:
    try:
        return await coro
    except UniFiApiError as err:
        _LOGGER.warning("UniFi-Service fehlgeschlagen: %s", err)
        raise HomeAssistantError(str(err)) from err


def _find(c: UniFiCoordinator, dataset: str, ident: str) -> dict:
    try:
        return c.find(dataset, ident)
    except UniFiApiError as err:
        raise ServiceValidationError(str(err)) from err


@callback
def async_setup_services(hass: HomeAssistant) -> None:

    # ------------------------------------------------------------ generisch
    async def api_request(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        method = call.data["method"]
        coro = c.client.request(method, call.data["path"], call.data.get("payload"))
        result = await _run(coro if method == "GET" else c.async_command(coro))
        return {"data": result if call.data.get("include_secrets") else redact(result)}

    async def get_objects(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        dataset = call.data[ATTR_RESOURCE]
        if call.data.get("refresh") or dataset not in c.data.config:
            objs = await _run(c.client.list_objects(DATASETS[dataset]))
        else:
            objs = list(c.data.config[dataset].values())
        if name := call.data.get("filter"):
            objs = [o for o in objs if name.lower() in object_name(o).lower()]
        if not call.data.get("include_secrets"):
            objs = redact(objs)
        return {"resource": dataset, "count": len(objs), "objects": objs}

    async def update_object(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        dataset = call.data[ATTR_RESOURCE]
        obj = _find(c, dataset, call.data[ATTR_OBJECT])
        result = await _run(c.async_update_object(dataset, obj, call.data["changes"]))
        return {"data": redact(result)}

    async def create_object(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        path = DATASETS[call.data[ATTR_RESOURCE]]
        result = await _run(c.async_command(c.client.create_object(path, call.data["data"])))
        return {"data": redact(result)}

    async def delete_object(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        dataset = call.data[ATTR_RESOURCE]
        obj = _find(c, dataset, call.data[ATTR_OBJECT])
        await _run(c.async_command(c.client.delete_object(DATASETS[dataset], obj["_id"])))

    async def set_enabled(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        dataset = call.data[ATTR_RESOURCE]
        obj = _find(c, dataset, call.data[ATTR_OBJECT])
        await _run(c.async_update_object(dataset, obj, {"enabled": call.data["enabled"]}))

    async def refresh(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        c._force_config = True  # noqa: SLF001
        await c.async_refresh()

    # ------------------------------------------------------------ Logs / Fail2Ban
    async def get_logs(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        now = int(time.time() * 1000)
        res = await _run(c.logs.fetch(
            now - call.data["hours"] * 3_600_000, now, 0, call.data["limit"]))
        entries = [parse_entry(i) for i in res.get("data") or []]
        if cat := call.data.get("category"):
            entries = [e for e in entries if (e["category"] or "").upper() == cat.upper()]
        if text := call.data.get("filter"):
            entries = [e for e in entries if text.lower() in (e["message"] or "").lower()]
        return {"total": res.get("total_element_count"), "count": len(entries),
                "entries": entries}

    async def ban_ip(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c.logs.async_ban(
            call.data["ip"], call.data.get("minutes"), call.data.get("reason", "manuell")))

    async def unban_ip(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c.logs.async_unban(call.data["ip"]))

    async def get_bans(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        return {"group": c.logs.group_name, "bans": c.logs.ban_list()}

    # ------------------------------------------------------------ Secrets
    async def regenerate_vpn_key(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        net = _find(c, "networks", call.data["vpn"])
        return await _run(async_rotate_wireguard(c, net))

    async def regenerate_wlan_password(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        wlan = _find(c, "wlans", call.data["wlan"])
        res = await _run(async_rotate_wlan(
            c, wlan, call.data["length"], notify=call.data["notify"]))
        return res if call.return_response else {k: v for k, v in res.items() if k != "passphrase"}

    # ------------------------------------------------------------ Länder-Blocking
    async def set_region_blocking(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        st = await _run(async_apply(
            c, enabled=call.data.get("enabled"), countries=call.data.get("countries"),
            add=call.data.get("add"), remove=call.data.get("remove"),
            exceptions=call.data.get("exceptions"), zones=call.data.get("zones"),
            wireguard=call.data.get("wireguard")))
        return {**st, "names": country_names(st["countries"])}

    # ------------------------------------------------------------ Flows / VPN / Betrieb / Apps
    async def get_flows(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        return await _run(async_query(
            c, minutes=call.data["minutes"], client=call.data.get("client"),
            action=call.data["action"], policy=call.data.get("policy"),
            destination=call.data.get("destination"), limit=call.data["limit"]))

    async def create_vpn_client(call: ServiceCall) -> ServiceResponse:
        from .wireguard import async_create_client  # noqa: PLC0415

        c = _coordinator(hass, call)
        res = await _run(async_create_client(
            c, name=call.data["name"], vpn=call.data.get("vpn"),
            allowed_ips=call.data.get("allowed_ips"), dns=call.data.get("dns"),
            endpoint=call.data.get("endpoint"), notify=call.data["notify"]))
        return res if call.return_response else {k: v for k, v in res.items() if k != "config"}

    async def delete_vpn_client(call: ServiceCall) -> ServiceResponse:
        from .wireguard import async_delete_client  # noqa: PLC0415

        c = _coordinator(hass, call)
        return await _run(async_delete_client(c, name=call.data["name"], vpn=call.data.get("vpn")))

    async def run_speedtest(call: ServiceCall) -> None:
        from .button import async_run_speedtest  # noqa: PLC0415

        await _run(async_run_speedtest(_coordinator(hass, call)))

    async def create_backup(call: ServiceCall) -> ServiceResponse:
        from .button import async_create_backup  # noqa: PLC0415

        return await _run(async_create_backup(_coordinator(hass, call)))

    async def set_app_block(call: ServiceCall) -> None:
        from .switch import async_set_app_block  # noqa: PLC0415

        c = _coordinator(hass, call)
        net = _find(c, "networks", call.data["network"])
        await _run(async_set_app_block(c, net["_id"], call.data["app"], call.data["blocked"]))

    # ------------------------------------------------------------ Kinderprofile
    def _kid(c: UniFiCoordinator, ident: str):
        kid = c.kids.find(ident) if c.kids else None
        if kid is None:
            raise ServiceValidationError(f"Kinderprofil „{ident}“ nicht gefunden")
        return kid

    async def add_kid(call: ServiceCall) -> ServiceResponse:
        import time as _t  # noqa: PLC0415
        from types import MappingProxyType  # noqa: PLC0415

        from homeassistant.config_entries import ConfigSubentry  # noqa: PLC0415

        from .kids import SUBENTRY_KID, async_create_network  # noqa: PLC0415

        c = _coordinator(hass, call)
        entry = c.config_entry
        name = call.data["name"].strip()
        if any(s.subentry_type == SUBENTRY_KID and s.title.lower() == name.lower()
               for s in entry.subentries.values()):
            raise ServiceValidationError(f"Kinderprofil „{name}“ existiert bereits")
        network = call.data.get("network")
        if network:
            net_id = _find(c, "networks", network)["_id"]
        else:
            net_id = await _run(async_create_network(c, name))
        data = {"name": name, "network_id": net_id, "rev": _t.time(),
                **{k: call.data[k] for k in ("unlock", "lock_school", "lock_weekend", "schedule",
                                             "free_calendars", "free_filter_calendars",
                                             "free_filter")
                   if k in call.data}}
        hass.config_entries.async_add_subentry(entry, ConfigSubentry(
            data=MappingProxyType(data), subentry_type=SUBENTRY_KID, title=name, unique_id=net_id))
        return {"name": name, "network_id": net_id}

    async def assign_device(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        target = call.data.get("kid")
        net_id = None
        if target and target.lower() not in ("none", "keins", "-"):
            kid = c.kids.find(target) if c.kids else None
            net_id = kid.network_id if kid else _find(c, "networks", target)["_id"]
        await _run(c.kids.async_assign_device(call.data["mac"], net_id))

    async def kid_bonus(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        until = await _run(_kid(c, call.data["kid"]).async_bonus(call.data["minutes"]))
        return {"bonus_bis": until.isoformat()}

    async def kid_free_days(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        kid = _kid(c, call.data["kid"])
        await kid.async_set_free_days(call.data.get("free_calendars"), call.data.get("free_filter"),
                                      call.data.get("free_filter_calendars"))
        p = kid.plan
        return {"naechste_sperre": p["at"].isoformat() if p.get("at") else None,
                "grund": p.get("reason"), "kalender": kid.free_calendars,
                "kalender_gefiltert": kid.free_filter_calendars, "filter": kid.free_filter}

    async def kid_internet(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        kid = _kid(c, call.data["kid"])
        if not call.data["online"]:
            await kid.async_cancel_bonus()
        await _run(kid.async_set_online(call.data["online"], "Service"))

    # ------------------------------------------------------------ Benachrichtigungen
    async def notify(call: ServiceCall) -> ServiceResponse:
        from .notifications import async_send  # noqa: PLC0415

        c = _coordinator(hass, call)
        sent = await async_send(hass, c.config_entry.options, call.data["category"],
                                call.data["title"], call.data["message"], call.data.get("data"))
        return {"empfaenger": sent}

    # ------------------------------------------------------------ Aktionen
    async def stamgr(cmd: str, call: ServiceCall, **extra: Any) -> None:
        c = _coordinator(hass, call)
        await _run(c.async_command(c.client.stamgr(cmd, call.data[ATTR_MAC], **extra)))

    async def block_client(call: ServiceCall) -> None:
        await stamgr("block-sta", call)

    async def unblock_client(call: ServiceCall) -> None:
        await stamgr("unblock-sta", call)

    async def reconnect_client(call: ServiceCall) -> None:
        await stamgr("kick-sta", call)

    async def forget_client(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c.async_command(
            c.client.request("POST", "cmd/stamgr",
                             {"cmd": "forget-sta", "macs": [call.data[ATTR_MAC].lower()]})))

    async def authorize_guest(call: ServiceCall) -> None:
        extra = {"minutes": call.data["minutes"]} if "minutes" in call.data else {}
        await stamgr("authorize-guest", call, **extra)

    async def unauthorize_guest(call: ServiceCall) -> None:
        await stamgr("unauthorize-guest", call)

    async def restart_device(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c.async_command(c.client.devmgr("restart", call.data[ATTR_MAC])))

    async def power_cycle_port(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c.async_command(c.client.devmgr(
            "power-cycle", call.data[ATTR_MAC], port_idx=call.data["port_idx"])))

    async def set_wlan(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        obj = _find(c, "wlans", call.data["wlan"])
        changes: dict[str, Any] = {}
        if "enabled" in call.data:
            changes["enabled"] = call.data["enabled"]
        if "passphrase" in call.data:
            changes["x_passphrase"] = call.data["passphrase"]
        if not changes:
            raise ServiceValidationError("enabled oder passphrase angeben")
        await _run(c.async_update_object("wlans", obj, changes))

    reg = hass.services.async_register
    reg(DOMAIN, "api_request", api_request, schema=vol.Schema({
        **BASE,
        vol.Required("method", default="GET"): vol.All(
            cv.string, vol.Upper, vol.In(["GET", "POST", "PUT", "DELETE"])),
        vol.Required("path"): cv.string,
        vol.Optional("payload"): vol.Any(dict, list),
        vol.Optional("include_secrets", default=False): cv.boolean,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "get_objects", get_objects, schema=vol.Schema({
        **BASE,
        vol.Required(ATTR_RESOURCE): RESOURCE,
        vol.Optional("filter"): cv.string,
        vol.Optional("refresh", default=False): cv.boolean,
        vol.Optional("include_secrets", default=False): cv.boolean,
    }), supports_response=SupportsResponse.ONLY)
    reg(DOMAIN, "update_object", update_object, schema=vol.Schema({
        **BASE,
        vol.Required(ATTR_RESOURCE): RESOURCE,
        vol.Required(ATTR_OBJECT): cv.string,
        vol.Required("changes"): dict,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "create_object", create_object, schema=vol.Schema({
        **BASE,
        vol.Required(ATTR_RESOURCE): RESOURCE,
        vol.Required("data"): dict,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "delete_object", delete_object, schema=vol.Schema({
        **BASE,
        vol.Required(ATTR_RESOURCE): RESOURCE,
        vol.Required(ATTR_OBJECT): cv.string,
    }))
    reg(DOMAIN, "set_enabled", set_enabled, schema=vol.Schema({
        **BASE,
        vol.Required(ATTR_RESOURCE): RESOURCE,
        vol.Required(ATTR_OBJECT): cv.string,
        vol.Required("enabled"): cv.boolean,
    }))
    reg(DOMAIN, "refresh", refresh, schema=vol.Schema(BASE))
    reg(DOMAIN, "get_logs", get_logs, schema=vol.Schema({
        **BASE,
        vol.Optional("hours", default=24): vol.All(vol.Coerce(int), vol.Range(min=1, max=720)),
        vol.Optional("limit", default=100): vol.All(vol.Coerce(int), vol.Range(min=1, max=1000)),
        vol.Optional("category"): cv.string,
        vol.Optional("filter"): cv.string,
    }), supports_response=SupportsResponse.ONLY)
    reg(DOMAIN, "ban_ip", ban_ip, schema=vol.Schema({
        **BASE,
        vol.Required("ip"): vol.All(cv.string, _valid_ip),
        vol.Optional("minutes"): vol.All(vol.Coerce(int), vol.Range(min=1)),
        vol.Optional("reason"): cv.string,
    }))
    reg(DOMAIN, "unban_ip", unban_ip, schema=vol.Schema({
        **BASE, vol.Required("ip"): vol.All(cv.string, _valid_ip)}))
    reg(DOMAIN, "regenerate_vpn_key", regenerate_vpn_key, schema=vol.Schema({
        **BASE, vol.Required("vpn"): cv.string}), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "regenerate_wlan_password", regenerate_wlan_password, schema=vol.Schema({
        **BASE,
        vol.Required("wlan"): cv.string,
        vol.Optional("length", default=24): vol.All(vol.Coerce(int), vol.Range(min=12, max=63)),
        vol.Optional("notify", default=True): cv.boolean,
    }), supports_response=SupportsResponse.OPTIONAL)
    codes = vol.All(cv.ensure_list, [vol.All(cv.string, vol.Upper, vol.Length(min=2, max=2))])
    reg(DOMAIN, "set_region_blocking", set_region_blocking, schema=vol.Schema({
        **BASE,
        vol.Optional("enabled"): cv.boolean,
        vol.Optional("countries"): codes,
        vol.Optional("add"): codes,
        vol.Optional("remove"): codes,
        vol.Optional("exceptions"): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional("zones"): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional("wireguard"): cv.boolean,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "get_flows", get_flows, schema=vol.Schema({
        **BASE,
        vol.Optional("minutes", default=30): vol.All(vol.Coerce(int), vol.Range(min=1, max=1440)),
        vol.Optional("client"): cv.string,
        vol.Optional("action", default="blocked"): vol.In(["blocked", "allowed", "all"]),
        vol.Optional("policy"): cv.string,
        vol.Optional("destination"): cv.string,
        vol.Optional("limit", default=50): vol.All(vol.Coerce(int), vol.Range(min=1, max=500)),
    }), supports_response=SupportsResponse.ONLY)
    reg(DOMAIN, "create_vpn_client", create_vpn_client, schema=vol.Schema({
        **BASE,
        vol.Required("name"): vol.All(cv.string, vol.Length(min=1, max=64)),
        vol.Optional("vpn"): cv.string,
        vol.Optional("allowed_ips"): cv.string,
        vol.Optional("dns"): cv.string,
        vol.Optional("endpoint"): cv.string,
        vol.Optional("notify", default=True): cv.boolean,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "delete_vpn_client", delete_vpn_client, schema=vol.Schema({
        **BASE, vol.Required("name"): cv.string, vol.Optional("vpn"): cv.string,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "run_speedtest", run_speedtest, schema=vol.Schema(BASE))
    reg(DOMAIN, "create_backup", create_backup, schema=vol.Schema(BASE),
        supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "set_app_block", set_app_block, schema=vol.Schema({
        **BASE,
        vol.Required("network"): cv.string,
        vol.Required("app"): vol.In(list(APP_DOMAINS)),
        vol.Required("blocked"): cv.boolean,
    }))
    hhmm = vol.All(cv.time, lambda t: t.isoformat())
    reg(DOMAIN, "add_kid", add_kid, schema=vol.Schema({
        **BASE,
        vol.Required("name"): vol.All(cv.string, vol.Length(min=1, max=40)),
        vol.Optional("network"): cv.string,
        vol.Optional("unlock"): hhmm,
        vol.Optional("lock_school"): hhmm,
        vol.Optional("lock_weekend"): hhmm,
        vol.Optional("schedule"): cv.boolean,
        vol.Optional("free_calendars"): cv.entity_ids,
        vol.Optional("free_filter_calendars"): cv.entity_ids,
        vol.Optional("free_filter"): cv.string,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "kid_free_days", kid_free_days, schema=vol.Schema({
        **BASE, vol.Required("kid"): cv.string,
        vol.Optional("free_calendars"): cv.entity_ids,
        vol.Optional("free_filter_calendars"): cv.entity_ids,
        vol.Optional("free_filter"): cv.string,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "assign_device", assign_device, schema=vol.Schema({
        **BASE, vol.Required("mac"): cv.string, vol.Optional("kid"): cv.string,
    }))
    reg(DOMAIN, "kid_bonus", kid_bonus, schema=vol.Schema({
        **BASE, vol.Required("kid"): cv.string,
        vol.Optional("minutes", default=30): vol.All(vol.Coerce(int), vol.Range(min=5, max=480)),
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "kid_internet", kid_internet, schema=vol.Schema({
        **BASE, vol.Required("kid"): cv.string, vol.Required("online"): cv.boolean,
    }))
    from .notifications import NOTIFY_CATEGORIES  # noqa: PLC0415

    reg(DOMAIN, "notify", notify, schema=vol.Schema({
        **BASE,
        vol.Required("category"): vol.In(list(NOTIFY_CATEGORIES)),
        vol.Required("title"): cv.string,
        vol.Required("message"): cv.string,
        vol.Optional("data"): dict,
    }), supports_response=SupportsResponse.OPTIONAL)
    reg(DOMAIN, "get_bans", get_bans, schema=vol.Schema(BASE),
        supports_response=SupportsResponse.ONLY)
    for name, func in (
        ("block_client", block_client),
        ("unblock_client", unblock_client),
        ("reconnect_client", reconnect_client),
        ("forget_client", forget_client),
        ("unauthorize_guest", unauthorize_guest),
        ("restart_device", restart_device),
    ):
        reg(DOMAIN, name, func, schema=MAC_SCHEMA)
    reg(DOMAIN, "authorize_guest", authorize_guest,
        schema=MAC_SCHEMA.extend({vol.Optional("minutes"): vol.All(int, vol.Range(min=1))}))
    reg(DOMAIN, "power_cycle_port", power_cycle_port,
        schema=MAC_SCHEMA.extend({vol.Required("port_idx"): vol.All(int, vol.Range(min=1))}))
    reg(DOMAIN, "set_wlan", set_wlan, schema=vol.Schema({
        **BASE,
        vol.Required("wlan"): cv.string,
        vol.Optional("enabled"): cv.boolean,
        vol.Optional("passphrase"): vol.All(cv.string, vol.Length(min=8, max=63)),
    }))
