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
    Platform.TIME,
    Platform.UPDATE,
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
CONF_NEW_CLIENT_NOTIFY = "new_client_notify"
CONF_KID_NETWORKS = "kid_networks"
CONF_VPN_ENDPOINT = "vpn_endpoint"

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
CONF_F2B_INSTANT = "f2b_instant_events"
CONF_F2B_HA_LOGIN = "f2b_ha_login"
CONF_F2B_BANTIME_INSTANT = "f2b_bantime_instant"
CONF_F2B_RECIDIVE = "f2b_recidive"

DEFAULT_LOG_FILE = ""
DEFAULT_F2B_MAXRETRY = 5
DEFAULT_F2B_FINDTIME = 600      # s
DEFAULT_F2B_BANTIME = 60        # min, 0 = dauerhaft
DEFAULT_F2B_CATEGORIES = "SECURITY"
DEFAULT_BAN_GROUP = "HA Fail2Ban"
DEFAULT_F2B_INSTANT = "THREAT_BLOCKED,THREAT_DETECTED"
DEFAULT_F2B_BANTIME_INSTANT = 1440   # min
DEFAULT_F2B_RECIDIVE = 3             # ab der n-ten Sperre dauerhaft, 0 = aus
BAN_PLACEHOLDER = "192.0.2.1"   # TEST-NET-1, hält die Gruppe nicht leer

EVENT_LOG = f"{DOMAIN}_log"
EVENT_ALERT = f"{DOMAIN}_alert"
EVENT_BAN = f"{DOMAIN}_ban"
EVENT_NEW_CLIENT = f"{DOMAIN}_new_client"
