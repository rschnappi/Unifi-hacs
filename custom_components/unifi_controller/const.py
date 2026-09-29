"""Konstanten für UniFi Controller Manager."""
from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "unifi_controller"
MANUFACTURER = "Ubiquiti"

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.EVENT,
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

CONF_API_KEY = "api_key"

# Logs / Fail2Ban
CONF_LOGS = "logs_enabled"
CONF_LOG_FILE = "log_file"
CONF_LOG_BACKFILL = "log_backfill_minutes"
CONF_F2B = "f2b_enabled"
CONF_F2B_MAXRETRY = "f2b_maxretry"
CONF_F2B_FINDTIME = "f2b_findtime"
CONF_F2B_BANTIME = "f2b_bantime"
CONF_F2B_CATEGORIES = "f2b_categories"
CONF_F2B_WHITELIST = "f2b_whitelist"
CONF_BAN_GROUP = "ban_group"

DEFAULT_LOG_FILE = ""
DEFAULT_F2B_MAXRETRY = 5
DEFAULT_F2B_FINDTIME = 600      # s
DEFAULT_F2B_BANTIME = 60        # min, 0 = dauerhaft
DEFAULT_F2B_CATEGORIES = "SECURITY"
DEFAULT_BAN_GROUP = "HA Fail2Ban"
BAN_PLACEHOLDER = "192.0.2.1"   # TEST-NET-1, hält die Gruppe nicht leer

EVENT_LOG = f"{DOMAIN}_log"
EVENT_BAN = f"{DOMAIN}_ban"
