"""Services: generischer API-Zugriff + gängige Client/Geräte/WLAN-Aktionen."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .api import UniFiApiError
from .const import DOMAIN
from .coordinator import UniFiCoordinator

ATTR_ENTRY = "config_entry_id"
ATTR_MAC = "mac"

BASE = {vol.Optional(ATTR_ENTRY): cv.string}
MAC_SCHEMA = vol.Schema({**BASE, vol.Required(ATTR_MAC): cv.string})


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


async def _run(coordinator: UniFiCoordinator, coro) -> Any:
    try:
        return await coordinator.async_command(coro)
    except UniFiApiError as err:
        raise HomeAssistantError(str(err)) from err


@callback
def async_setup_services(hass: HomeAssistant) -> None:

    async def api_request(call: ServiceCall) -> ServiceResponse:
        c = _coordinator(hass, call)
        method = call.data["method"]
        coro = c.client.request(method, call.data["path"], call.data.get("payload"))
        if method == "GET":
            try:
                result = await coro
            except UniFiApiError as err:
                raise HomeAssistantError(str(err)) from err
        else:
            result = await _run(c, coro)
        return {"data": result}

    async def stamgr(cmd: str, call: ServiceCall, **extra: Any) -> None:
        c = _coordinator(hass, call)
        await _run(c, c.client.stamgr(cmd, call.data[ATTR_MAC], **extra))

    async def block_client(call: ServiceCall) -> None:
        await stamgr("block-sta", call)

    async def unblock_client(call: ServiceCall) -> None:
        await stamgr("unblock-sta", call)

    async def reconnect_client(call: ServiceCall) -> None:
        await stamgr("kick-sta", call)

    async def authorize_guest(call: ServiceCall) -> None:
        extra = {"minutes": call.data["minutes"]} if "minutes" in call.data else {}
        await stamgr("authorize-guest", call, **extra)

    async def restart_device(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c, c.client.devmgr("restart", call.data[ATTR_MAC]))

    async def power_cycle_port(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        await _run(c, c.client.devmgr("power-cycle", call.data[ATTR_MAC],
                                      port_idx=call.data["port_idx"]))

    async def set_wlan(call: ServiceCall) -> None:
        c = _coordinator(hass, call)
        ident = call.data["wlan"]
        wlan_id = next(
            (wid for wid, w in c.data.wlans.items() if ident in (wid, w.get("name"))), None
        )
        if wlan_id is None:
            raise ServiceValidationError(f"WLAN '{ident}' nicht gefunden")
        changes: dict[str, Any] = {}
        if "enabled" in call.data:
            changes["enabled"] = call.data["enabled"]
        if "passphrase" in call.data:
            changes["x_passphrase"] = call.data["passphrase"]
        if not changes:
            raise ServiceValidationError("enabled oder passphrase angeben")
        await _run(c, c.client.update_wlan(wlan_id, changes))

    hass.services.async_register(
        DOMAIN, "api_request", api_request,
        schema=vol.Schema({
            **BASE,
            vol.Required("method", default="GET"): vol.All(
                cv.string, vol.Upper, vol.In(["GET", "POST", "PUT", "DELETE"])),
            vol.Required("path"): cv.string,
            vol.Optional("payload"): vol.Any(dict, list),
        }),
        supports_response=SupportsResponse.OPTIONAL,
    )
    for name, func in (
        ("block_client", block_client),
        ("unblock_client", unblock_client),
        ("reconnect_client", reconnect_client),
        ("restart_device", restart_device),
    ):
        hass.services.async_register(DOMAIN, name, func, schema=MAC_SCHEMA)
    hass.services.async_register(
        DOMAIN, "authorize_guest", authorize_guest,
        schema=MAC_SCHEMA.extend({vol.Optional("minutes"): vol.All(int, vol.Range(min=1))}),
    )
    hass.services.async_register(
        DOMAIN, "power_cycle_port", power_cycle_port,
        schema=MAC_SCHEMA.extend({vol.Required("port_idx"): vol.All(int, vol.Range(min=1))}),
    )
    hass.services.async_register(
        DOMAIN, "set_wlan", set_wlan,
        schema=vol.Schema({
            **BASE,
            vol.Required("wlan"): cv.string,
            vol.Optional("enabled"): cv.boolean,
            vol.Optional("passphrase"): vol.All(cv.string, vol.Length(min=8, max=63)),
        }),
    )
