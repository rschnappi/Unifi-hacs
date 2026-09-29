"""Konstanten für UniFi Controller Manager."""
from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "unifi_controller"
MANUFACTURER = "Ubiquiti"

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.SENSOR,
    Platform.SWITCH,
]

CONF_SITE = "site"
CONF_SECRET_NAME = "secret_name"

CONF_PREFIX = "prefix"
CONF_CLIENT_SWITCHES = "client_switches"
CONF_CONFIG_INTERVAL = "config_interval"
CONF_SWITCH_GROUPS = "switch_groups"

DEFAULT_HOST = "192.168.99.1"
DEFAULT_SITE = "default"
DEFAULT_SECRET_NAME = "unifi_api_key"
DEFAULT_PREFIX = "Netz"
DEFAULT_SCAN_INTERVAL = 30
DEFAULT_CONFIG_INTERVAL = 120
