"""Buttons: Neustart, PoE Power-Cycle, Schlüssel/Passwörter, Speedtest, Controller-Backup."""
from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import UniFiApiError
from .coordinator import UniFiConfigEntry, UniFiCoordinator
from .kid_entities import kid_entities
from .entity import ControllerEntity, DeviceEntity, async_add_dynamic
from .resources import object_name, stable_id
from .secrets_mgmt import async_rotate_wireguard, async_rotate_wlan, is_wireguard


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UniFiConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def factory():
        yield SpeedtestButton(coordinator)
        yield BackupButton(coordinator)
        for net_id, net in coordinator.data.config.get("networks", {}).items():
            if is_wireguard(net):
                yield RotateWireguardButton(coordinator, net_id)
        for wlan_id in coordinator.data.config.get("wlans", {}):
            yield RotateWlanButton(coordinator, wlan_id)
        for mac, dev in coordinator.data.devices.items():
            yield RestartButton(coordinator, mac)
            for port in dev.get("port_table", []):
                if port.get("port_poe"):
                    yield PowerCycleButton(coordinator, mac, port["port_idx"])

    async_add_dynamic(coordinator, async_add_entities, factory)
    for sid, ents in kid_entities(coordinator, "button").items():
        async_add_entities(ents, config_subentry_id=sid)


class RestartButton(DeviceEntity, ButtonEntity):
    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, mac: str) -> None:
        super().__init__(coordinator, mac, "restart", "Neustart")

    async def async_press(self) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("restart", self._mac))


class PowerCycleButton(DeviceEntity, ButtonEntity):
    _attr_icon = "mdi:power-cycle"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, mac: str, port_idx: int) -> None:
        super().__init__(coordinator, mac, f"power_cycle_{port_idx}", f"Port {port_idx} Power-Cycle")
        self._idx = port_idx

    async def async_press(self) -> None:
        await self.coordinator.async_command(
            self.coordinator.client.devmgr("power-cycle", self._mac, port_idx=self._idx))


class RotateWireguardButton(ControllerEntity, ButtonEntity):
    """Neuen WireGuard-Serverschlüssel erzeugen (Clients brauchen neue Configs)."""

    _attr_icon = "mdi:key-change"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator, net_id: str) -> None:
        net = coordinator.data.config["networks"][net_id]
        super().__init__(coordinator, f"rotate_wg_{stable_id(net, net_id)}",
                         f"VPN {object_name(net)} Schlüssel neu erzeugen")
        self._id = net_id

    async def async_press(self) -> None:
        net = self.coordinator.data.config.get("networks", {}).get(self._id)
        if not net:
            raise HomeAssistantError("VPN nicht mehr vorhanden")
        try:
            await async_rotate_wireguard(self.coordinator, net)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err


class RotateWlanButton(ControllerEntity, ButtonEntity):
    """Neues WLAN-Passwort (Anzeige als Benachrichtigung). Standardmäßig deaktiviert."""

    _attr_icon = "mdi:form-textbox-password"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: UniFiCoordinator, wlan_id: str) -> None:
        wlan = coordinator.data.config["wlans"][wlan_id]
        super().__init__(coordinator, f"rotate_wlan_{stable_id(wlan, wlan_id)}",
                         f"WLAN {object_name(wlan)} Passwort neu erzeugen")
        self._id = wlan_id

    async def async_press(self) -> None:
        wlan = self.coordinator.data.config.get("wlans", {}).get(self._id)
        if not wlan:
            raise HomeAssistantError("WLAN nicht mehr vorhanden")
        try:
            await async_rotate_wlan(self.coordinator, wlan, 24, notify=True)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err


class SpeedtestButton(ControllerEntity, ButtonEntity):
    """Speedtest am Gateway starten (Ergebnis nach ~1 min in den Speedtest-Sensoren)."""

    _attr_icon = "mdi:speedometer"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "speedtest_run", "Speedtest starten")

    async def async_press(self) -> None:
        try:
            await async_run_speedtest(self.coordinator)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err


class BackupButton(ControllerEntity, ButtonEntity):
    """Controller-Backup erzeugen, herunterladen und unter /config/unifi_controller_backups ablegen."""

    _attr_icon = "mdi:content-save-cog"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "controller_backup_run", "Controller-Backup erstellen")

    async def async_press(self) -> None:
        try:
            await async_create_backup(self.coordinator)
        except UniFiApiError as err:
            raise HomeAssistantError(str(err)) from err


async def async_run_speedtest(coordinator: UniFiCoordinator) -> None:
    await coordinator.client.request("POST", "cmd/devmgr", {"cmd": "speedtest"})

    # Ergebnis kommt verzögert – Konfig (inkl. Speedtest-Verlauf) in 90 s neu laden
    def _later(_now=None) -> None:
        coordinator._force_config = True  # noqa: SLF001
        coordinator.hass.async_create_task(coordinator.async_refresh())

    coordinator.hass.loop.call_later(90, _later)


BACKUP_DIR = "unifi_controller_backups"
BACKUP_KEEP = 10


def _save_backup(config_dir: str, data: bytes, version: str) -> str:
    import os  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    folder = os.path.join(config_dir, BACKUP_DIR)
    os.makedirs(folder, exist_ok=True)
    name = f"unifi_{version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.unf"
    path = os.path.join(folder, name)
    with open(path, "wb") as fh:
        fh.write(data)
    files = sorted(f for f in os.listdir(folder) if f.endswith(".unf"))
    for old in files[:-BACKUP_KEEP]:
        os.remove(os.path.join(folder, old))
    return path


async def async_create_backup(coordinator: UniFiCoordinator) -> dict:
    """Backup am Controller erzeugen, herunterladen und unter /config ablegen."""
    res = await coordinator.client.request("POST", "cmd/backup", {"cmd": "backup", "days": 0})
    url = (res[0] if isinstance(res, list) and res else res or {}).get("url")
    if not url:
        raise UniFiApiError("Controller hat keine Backup-Datei geliefert")
    data = await coordinator.client.download(url)
    if len(data) < 1024:
        raise UniFiApiError(f"Backup-Datei unplausibel klein ({len(data)} Byte)")
    version = coordinator.data.sysinfo.get("version", "x") if coordinator.data else "x"
    path = await coordinator.hass.async_add_executor_job(
        _save_backup, coordinator.hass.config.config_dir, data, version)
    return {"path": path, "size_kb": round(len(data) / 1024)}
