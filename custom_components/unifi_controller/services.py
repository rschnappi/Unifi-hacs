"""Services: generische CRUD-Operationen, Logs/Fail2Ban, Länder-Blocking, Secrets, Aktionen."""
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
