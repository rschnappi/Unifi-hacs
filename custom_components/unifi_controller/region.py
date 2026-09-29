"""Länder-Blocking (UniFi Region Blocking, Setting 'usg_geo')."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .api import UniFiApiError
from .countries import COUNTRIES

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator, UniFiData

ACTIONS = ["block", "allow"]            # block = Liste sperren, allow = nur Liste erlauben
DIRECTIONS = ["both", "ingress", "egress"]


def geo_setting(data: UniFiData | None) -> dict | None:
    if not data:
        return None
    for obj in data.config.get("settings", {}).values():
        if obj.get("key") == "usg_geo":
            return obj
    return None


def geo_state(setting: dict | None) -> dict[str, Any]:
    f = (setting or {}).get("ip_filtering") or {}
    raw = f.get("countries") or ""
    codes = raw if isinstance(raw, list) else [c.strip() for c in raw.split(",")]
    return {
        "enabled": bool(f.get("enabled")),
        "action": f.get("action") or "block",
        "traffic_direction": f.get("traffic_direction") or "both",
        "countries": sorted({c.upper() for c in codes if c}),
    }


def country_names(codes: list[str]) -> list[str]:
    return [f"{COUNTRIES.get(c, c)} ({c})" for c in codes]


async def async_set_geo(coordinator: UniFiCoordinator, *, enabled: bool | None = None,
                        action: str | None = None, traffic_direction: str | None = None,
                        countries: list[str] | None = None, add: list[str] | None = None,
                        remove: list[str] | None = None) -> dict[str, Any]:
    setting = geo_setting(coordinator.data)
    if setting is None:
        raise UniFiApiError("Region Blocking (usg_geo) wird von diesem Controller nicht angeboten")
    new = geo_state(setting)
    if countries is not None:
        new["countries"] = sorted({c.upper() for c in countries})
    if add:
        new["countries"] = sorted(set(new["countries"]) | {c.upper() for c in add})
    if remove:
        new["countries"] = sorted(set(new["countries"]) - {c.upper() for c in remove})
    unknown = [c for c in new["countries"] if c not in COUNTRIES]
    if unknown:
        raise UniFiApiError(f"Unbekannte Ländercodes: {', '.join(unknown)}")
    if enabled is not None:
        new["enabled"] = enabled
    if action is not None:
        new["action"] = action
    if traffic_direction is not None:
        new["traffic_direction"] = traffic_direction
    if new["enabled"] and not new["countries"]:
        raise UniFiApiError("Länder-Blocking braucht mindestens ein Land")
    body = {
        "key": "usg_geo",
        "ip_filtering": {
            "enabled": new["enabled"],
            "action": new["action"],
            "traffic_direction": new["traffic_direction"],
            "countries": ",".join(new["countries"]),   # Controller erwartet CSV-String
        },
    }
    await coordinator.async_command(
        coordinator.client.update_object("rest/setting/usg_geo", setting["_id"], body))
    return new
