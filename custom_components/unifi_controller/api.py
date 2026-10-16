"""Schlanker async Client für die UniFi Network API (UniFi OS, API-Key)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util.yaml import load_yaml_dict

_LOGGER = logging.getLogger(__name__)

TIMEOUT = 25
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
RETRY_DELAY = 0.5
# lesende POST-Abfragen dürfen wie GET wiederholt werden
READ_POSTS = ("v2/system-log/", "v2/traffic-flows", "stat/report/", "stat/sitedpi", "stat/stadpi")


class UniFiApiError(HomeAssistantError):
    """Allgemeiner API-Fehler."""


class UniFiAuthError(UniFiApiError):
    """API-Key ungültig oder ohne Berechtigung."""


class UniFiTransientError(UniFiApiError):
    """Vorübergehender Fehler (Timeout, HTTP 5xx, kaputte Antwort) – Wiederholung sinnvoll."""


def _read_secret(path: str, name: str) -> str | None:
    try:
        data = load_yaml_dict(path)
    except (FileNotFoundError, HomeAssistantError):
        return None
    value = data.get(name)
    return str(value) if value else None


async def async_load_secret(hass: HomeAssistant, name: str) -> str | None:
    """API-Key aus secrets.yaml lesen (wird nie im Config-Entry gespeichert)."""
    return await hass.async_add_executor_job(
        _read_secret, hass.config.path("secrets.yaml"), name
    )


async def async_get_api_key(hass: HomeAssistant, data: Any) -> str | None:
    """API-Key direkt aus dem Eintrag oder – falls gesetzt – aus secrets.yaml."""
    if key := (data.get("api_key") or "").strip():
        return key
    if name := (data.get("secret_name") or "").strip():
        return await async_load_secret(hass, name)
    return None


SITE_PLACEHOLDERS = ("{site}", "{siteId}")
PAGE_LIMIT = 200          # Maximum der meisten Integration-API-Listen
MAX_ITEMS = 5000


def _integration_error(text: str) -> str | None:
    """Fehlertext der offiziellen API (statusName/code/message) lesbar machen."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict) and data.get("message"):
        code = data.get("code") or data.get("statusName") or ""
        return f"{data['message']} ({code})" if code else str(data["message"])
    return None


class UniFiClient:
    """Zugriff auf Legacy-API (/api/s/<site>), v2-API und Integration-API."""

    def __init__(
        self, session: aiohttp.ClientSession, host: str, api_key: str, site: str
    ) -> None:
        self._session = session
        self._api_key = api_key
        self.host = host
        self.site = site
        base = f"https://{host}/proxy/network"
        self._legacy = f"{base}/api/s/{site}/"
        self._v2 = f"{base}/v2/api/site/{site}/"
        self._integration = f"{base}/integration/v1/"
        self._site_id: str | None = None

    # ------------------------------------------------------------------ core
    def resolve(self, path: str) -> tuple[str, bool]:
        """Pfad -> (URL, legacy?). 'v2/…' und 'integration/…' werden gemappt."""
        path = path.strip().lstrip("/")
        if not path or ".." in path:
            raise UniFiApiError("Pfad nicht erlaubt")
        if path.startswith("v2/"):
            return self._v2 + path[3:], False
        if path.startswith("integration/"):
            return self._integration + path[12:], False
        return self._legacy + path, True

    async def site_id(self) -> str:
        """UUID der Site für die offizielle API (Site „default“ → internalReference)."""
        if self._site_id:
            return self._site_id
        res = await self.request("GET", "integration/sites?limit=200")
        sites = (res or {}).get("data", []) if isinstance(res, dict) else []
        for s in sites:
            if self.site in (s.get("internalReference"), s.get("id"), s.get("name")):
                self._site_id = s["id"]
                return self._site_id
        if len(sites) == 1:
            self._site_id = sites[0]["id"]
            return self._site_id
        raise UniFiApiError(f"Site {self.site} in der Integration-API nicht gefunden")

    async def _expand(self, path: str) -> str:
        if path.lstrip("/").startswith("integration/") and any(
                p in path for p in SITE_PLACEHOLDERS):
            sid = await self.site_id()
            for p in SITE_PLACEHOLDERS:
                path = path.replace(p, sid)
        return path

    async def integration(self, method: str, path: str, payload: Any = None) -> Any:
        """Aufruf der offiziellen API; ``path`` relativ zu integration/v1, {site} = Site-UUID."""
        return await self.request(method, f"integration/{path.lstrip('/')}", payload)

    async def integration_list(self, path: str, api_filter: str | None = None,
                               page: int = PAGE_LIMIT) -> list[dict]:
        """Alle Seiten einer Liste der offiziellen API (offset/limit/totalCount)."""
        from urllib.parse import quote  # noqa: PLC0415

        out: list[dict] = []
        offset = 0
        sep = "&" if "?" in path else "?"
        flt = f"&filter={quote(api_filter, safe='')}" if api_filter else ""
        while True:
            res = await self.integration(
                "GET", f"{path}{sep}offset={offset}&limit={page}{flt}") or {}
            batch = res.get("data", []) if isinstance(res, dict) else list(res)
            out.extend(batch)
            total = res.get("totalCount", len(out)) if isinstance(res, dict) else len(out)
            offset += len(batch)
            if not batch or offset >= total or len(out) >= MAX_ITEMS:
                return out

    async def request(self, method: str, path: str, payload: Any = None) -> Any:
        """API-Aufruf; lesende Aufrufe werden bei vorübergehenden Fehlern einmal wiederholt."""
        method = method.upper()
        path = await self._expand(path)
        if method not in ALLOWED_METHODS:
            raise UniFiApiError(f"Methode {method} nicht erlaubt")
        retry = method == "GET" or (
            method == "POST" and path.strip().lstrip("/").startswith(READ_POSTS))
        try:
            return await self._request_once(method, path, payload)
        except UniFiTransientError as err:
            if not retry:
                raise
            _LOGGER.debug("Wiederhole %s %s nach Fehler: %s", method, path, err)
            await asyncio.sleep(RETRY_DELAY)
            return await self._request_once(method, path, payload)

    async def _request_once(self, method: str, path: str, payload: Any = None) -> Any:
        url, legacy = self.resolve(path)
        headers = {"X-API-KEY": self._api_key, "Accept": "application/json"}
        try:
            async with asyncio.timeout(TIMEOUT):
                async with self._session.request(
                    method, url, json=payload, headers=headers
                ) as resp:
                    text = await resp.text()
                    if resp.status in (401, 403):
                        raise UniFiAuthError(f"HTTP {resp.status}")
                    if resp.status >= 500:
                        raise UniFiTransientError(f"HTTP {resp.status} {path}: {text[:2000]}")
                    if resp.status >= 400:
                        msg = (_integration_error(text) if not legacy else None) or text[:2000]
                        raise UniFiApiError(f"HTTP {resp.status} {path}: {msg}")
        except (aiohttp.ClientError, TimeoutError) as err:
            raise UniFiTransientError(f"Verbindung zu {self.host} fehlgeschlagen: {err}") from err

        if not text:
            return None
        try:
            data = json.loads(text)
        except ValueError as err:
            raise UniFiTransientError(f"Keine JSON-Antwort von {path}") from err

        if legacy and isinstance(data, dict) and "meta" in data:
            meta = data.get("meta") or {}
            if meta.get("rc") != "ok":
                raise UniFiApiError(meta.get("msg", "Unbekannter Fehler"))
            return data.get("data", [])
        return data

    async def download(self, url_path: str) -> bytes:
        """Binärdatei vom Network-Controller laden (z. B. /dl/backup/…)."""
        if not url_path.startswith("/dl/") or ".." in url_path:
            raise UniFiApiError("Download-Pfad nicht erlaubt")
        url = f"https://{self.host}/proxy/network{url_path}"
        try:
            async with asyncio.timeout(120):
                async with self._session.get(url, headers={"X-API-KEY": self._api_key}) as resp:
                    if resp.status >= 400:
                        raise UniFiApiError(f"HTTP {resp.status} beim Download {url_path}")
                    return await resp.read()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise UniFiApiError(f"Download fehlgeschlagen: {err}") from err

    # ----------------------------------------------------------------- reads
    async def get_sysinfo(self) -> dict[str, Any]:
        data = await self.request("GET", "stat/sysinfo")
        return data[0] if data else {}

    async def get_health(self) -> list[dict]:
        return await self.request("GET", "stat/health") or []

    async def get_devices(self) -> list[dict]:
        return await self.request("GET", "stat/device") or []

    async def get_clients(self) -> list[dict]:
        return await self.request("GET", "stat/sta") or []

    async def list_objects(self, path: str) -> list[dict]:
        data = await self.request("GET", path)
        if isinstance(data, dict):
            data = data.get("data", [])
        return data or []

    # ---------------------------------------------------------------- writes
    async def stamgr(self, cmd: str, mac: str, **extra: Any) -> Any:
        return await self.request(
            "POST", "cmd/stamgr", {"cmd": cmd, "mac": mac.lower(), **extra}
        )

    async def devmgr(self, cmd: str, mac: str, **extra: Any) -> Any:
        return await self.request(
            "POST", "cmd/devmgr", {"cmd": cmd, "mac": mac.lower(), **extra}
        )

    async def update_wlan(self, wlan_id: str, changes: dict[str, Any]) -> Any:
        return await self.request("PUT", f"rest/wlanconf/{wlan_id}", changes)

    async def set_led(self, device_id: str, mode: str) -> Any:
        return await self.request("PUT", f"rest/device/{device_id}", {"led_override": mode})

    async def set_port_poe(self, device: dict, port_idx: int, mode: str) -> Any:
        overrides = [dict(o) for o in device.get("port_overrides", [])]
        for override in overrides:
            if override.get("port_idx") == port_idx:
                override["poe_mode"] = mode
                break
        else:
            overrides.append({"port_idx": port_idx, "poe_mode": mode})
        return await self.request(
            "PUT", f"rest/device/{device['_id']}", {"port_overrides": overrides}
        )

    async def create_object(self, path: str, body: dict) -> Any:
        return await self.request("POST", path, body)

    async def update_object(self, path: str, obj_id: str, body: dict) -> Any:
        return await self.request("PUT", f"{path}/{obj_id}", body)

    async def delete_object(self, path: str, obj_id: str) -> Any:
        return await self.request("DELETE", f"{path}/{obj_id}")
