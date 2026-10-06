"""UniFi Controller Manager – Verwaltung des UniFi Network Controllers per API-Key."""
from __future__ import annotations

import logging
import re

from homeassistant.const import CONF_HOST, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import UniFiClient, async_get_api_key
from .const import CONF_KID_NETWORKS, CONF_SITE, DOMAIN, PLATFORMS
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .kids import KidManager
from .logs import LogManager
from .presence import PresenceManager
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
    _async_migrate_legacy_ids(hass, entry, coordinator)
    _async_migrate_unique_ids(hass, entry, coordinator)
    coordinator.kids = KidManager(hass, coordinator)
    await coordinator.kids.async_setup()
    coordinator.presence = PresenceManager(hass, coordinator)
    await coordinator.presence.async_setup()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


def legacy_id_map(config: dict[str, dict[str, dict]]) -> dict[str, str]:
    """Alte Objekt-ID → neue Objekt-ID (UniFi Network 11 liefert die alte als ``legacy_id``)."""
    out: dict[str, str] = {}
    for objs in config.values():
        if not isinstance(objs, dict):
            continue
        for oid, obj in objs.items():
            old = obj.get("legacy_id") if isinstance(obj, dict) else None
            if old and str(old) != str(oid):
                out[str(old)] = str(oid)
    return out


def plan_legacy_migration(
    unique_ids: dict[str, str], legacy: dict[str, str]
) -> list[tuple[str, str, str | None]]:
    """Plan für die Entity-Registry: (entity_id, neue Unique-ID, zu entfernendes Duplikat).

    ``unique_ids``: Unique-ID → entity_id aller Entitäten der Config-Entry.
    Eine Entität mit alter ID behält ihre entity_id und bekommt die neue Unique-ID; ein bereits
    unter der neuen Unique-ID entstandenes Duplikat (z. B. ``…_2``) wird entfernt.
    """
    if not legacy:
        return []
    rx = re.compile("|".join(re.escape(k) for k in sorted(legacy, key=len, reverse=True)))
    plan: list[tuple[str, str, str | None]] = []
    for uid, entity_id in unique_ids.items():
        if not rx.search(uid):
            continue
        new_uid = rx.sub(lambda m: legacy[m.group(0)], uid)
        dup = unique_ids.get(new_uid)
        same_platform = dup and dup.split(".", 1)[0] == entity_id.split(".", 1)[0]
        plan.append((entity_id, new_uid, dup if same_platform and dup != entity_id else None))
    return plan


def _async_migrate_legacy_ids(
    hass: HomeAssistant, entry: UniFiConfigEntry, coordinator: UniFiCoordinator
) -> None:
    """UniFi Network 11: Objekt-IDs wechseln von Mongo-IDs auf UUIDs (einmalig nachziehen).

    Entity-IDs, Verlauf, Dashboards und Automationen bleiben erhalten; Kinderprofile und die
    Option „Kindernetze“ zeigen danach auf die neuen Netz-IDs.
    """
    legacy = legacy_id_map(coordinator.data.config)
    if not legacy:
        return
    registry = er.async_get(hass)
    uids = {e.unique_id: e.entity_id
            for e in er.async_entries_for_config_entry(registry, entry.entry_id)}
    moved = removed = 0
    for entity_id, new_uid, dup in plan_legacy_migration(uids, legacy):
        if dup and registry.async_get(dup):
            registry.async_remove(dup)
            removed += 1
        if registry.async_get(entity_id):
            registry.async_update_entity(entity_id, new_unique_id=new_uid)
            moved += 1
    # Kinderprofile: gespeicherte Netz-ID
    for sub in list(entry.subentries.values()):
        nid = sub.data.get("network_id")
        if nid in legacy:
            hass.config_entries.async_update_subentry(
                entry, sub, data={**sub.data, "network_id": legacy[nid]},
                unique_id=legacy[nid] if sub.unique_id == nid else sub.unique_id)
            _LOGGER.info("Kinderprofil %s: Netz-ID %s → %s", sub.title, nid, legacy[nid])
    # Option „Kindernetze“ (App-Nutzung / App-Sperren)
    kid_nets = entry.options.get(CONF_KID_NETWORKS) or []
    if any(n in legacy for n in kid_nets):
        new_list = [legacy.get(n, n) for n in kid_nets]
        hass.config_entries.async_update_entry(
            entry, options={**entry.options, CONF_KID_NETWORKS: new_list})
        coordinator.apps._configured = new_list  # noqa: SLF001
    if moved or removed:
        _LOGGER.warning(
            "UniFi Network 11: %s Entitäten auf neue Objekt-IDs umgestellt, %s Duplikate entfernt",
            moved, removed)


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
    if (presence := getattr(entry.runtime_data, "presence", None)) is not None:
        presence.async_unload()
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok and entry.runtime_data.logs:
        await hass.async_add_executor_job(entry.runtime_data.logs.close)
    return ok
