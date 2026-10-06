"""Traffic-Flows: Abfrage/Diagnose, App-Erkennung über Domains, App-Nutzung pro Netz."""
from __future__ import annotations

from collections import Counter, defaultdict
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.util import dt as dt_util

from .api import UniFiApiError

if TYPE_CHECKING:
    from .coordinator import UniFiCoordinator

_LOGGER = logging.getLogger(__name__)

FLOWS_PATH = "v2/traffic-flows"
PAGE_SIZE = 500
MAX_PAGES = 10
APP_POLL_S = 300

# App -> Domains (Suffix-Treffer). Bewusst konservativ: nur eindeutige App-Domains.
APP_DOMAINS: dict[str, list[str]] = {
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
                "youtube-nocookie.com", "youtubei.googleapis.com"],
    "TikTok": ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
               "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "Snapchat": ["snapchat.com", "snapkit.com", "sc-cdn.net", "snap-dev.net",
                 "snapads.com", "feelinsonice-hrd.appspot.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net"],
    "Roblox": ["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"],
    "Fortnite": ["fortnite.com", "epicgames.com", "epicgames.dev", "unrealengine.com"],
    "Minecraft": ["minecraft.net", "mojang.com", "minecraftservices.com"],
    "Twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                "discord.media"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
}
DEFAULT_BLOCK_APPS = {"YouTube", "TikTok", "Instagram", "Snapchat", "Roblox"}


def app_for_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    d = domain.lower().rstrip(".")
    for app, suffixes in APP_DOMAINS.items():
        if any(d == s or d.endswith("." + s) for s in suffixes):
            return app
    return None


def flow_app(flow: dict) -> str | None:
    for dom in (flow.get("destination") or {}).get("domains") or []:
        if app := app_for_domain(dom):
            return app
    return None


async def async_fetch_flows(coordinator: UniFiCoordinator, ts_from: int, ts_to: int,
                            max_pages: int = MAX_PAGES) -> list[dict]:
    """Flows im Zeitfenster (ms) holen – seitenweise."""
    out: list[dict] = []
    for page in range(max_pages):
        res = await coordinator.client.request("POST", FLOWS_PATH, {
            "timestampFrom": ts_from, "timestampTo": ts_to,
            "pageNumber": page, "pageSize": PAGE_SIZE,
        })
        batch = (res or {}).get("data") or [] if isinstance(res, dict) else res or []
        out.extend(batch)
        if len(batch) < PAGE_SIZE or not (isinstance(res, dict) and res.get("has_next", True)):
            break
    return out


def simplify(f: dict) -> dict[str, Any]:
    src, dst = f.get("source") or {}, f.get("destination") or {}
    pols = [p.get("name") or p.get("internal_type") for p in f.get("policies") or []]
    return {
        "time": dt_util.utc_from_timestamp((f.get("time") or 0) / 1000).isoformat(),
        "action": f.get("action"),
        "protocol": f.get("protocol"),
        "service": f.get("service"),
        "source": src.get("client_name") or src.get("ip"),
        "source_ip": src.get("ip"),
        "source_port": src.get("port"),
        "source_network": src.get("network_name"),
        "destination": (dst.get("domains") or [None])[0] or dst.get("client_name") or dst.get("ip"),
        "destination_ip": dst.get("ip"),
        "destination_port": dst.get("port"),
        "destination_zone": dst.get("zone_name"),
        "region": dst.get("region"),
        "policy": ", ".join(p for p in pols if p),
        "app": flow_app(f),
        "bytes": (f.get("traffic_data") or {}).get("bytes_total"),
    }


def _match(value: Any, needle: str | None) -> bool:
    return not needle or needle.lower() in str(value or "").lower()


async def async_query(coordinator: UniFiCoordinator, *, minutes: int, client: str | None,
                      action: str, policy: str | None, destination: str | None,
                      limit: int) -> dict[str, Any]:
    """Service-Abfrage: gefilterte Flows + Zusammenfassung („Warum wird X geblockt?“)."""
    now = int(time.time() * 1000)
    flows = await async_fetch_flows(coordinator, now - minutes * 60_000, now)
    hits = []
    for f in flows:
        s = simplify(f)
        if action != "all" and s["action"] != action:
            continue
        if client and not (_match(s["source"], client) or _match(s["source_ip"], client)
                           or _match((f.get("source") or {}).get("mac"), client)):
            continue
        if not _match(s["policy"], policy):
            continue
        if destination and not (_match(s["destination"], destination)
                                or _match(s["destination_ip"], destination)):
            continue
        hits.append(s)

    def _port(p: Any) -> Any:
        return p if isinstance(p, int) and p < 32768 else ("dynamisch" if p else None)

    summary = Counter(
        (h["source"], h["protocol"], h["destination"], _port(h["destination_port"]), h["policy"])
        for h in hits
    )
    top = [
        {"source": k[0], "protocol": k[1], "destination": k[2], "port": k[3],
         "policy": k[4], "count": n}
        for k, n in summary.most_common(20)
    ]
    return {"minutes": minutes, "flows_total": len(flows), "matches": len(hits),
            "top": top, "flows": hits[:limit]}


def default_kid_networks(coordinator: UniFiCoordinator) -> list[str]:
    """Netze der Firewall-Zone „Kinder“ (Standard, falls nichts gewählt)."""
    data = coordinator.data
    if not data:
        return []
    zones = {zid for zid, z in data.config.get("firewall_zones", {}).items()
             if (z.get("name") or "").lower() in ("kinder", "kids", "children")}
    return [nid for nid, n in data.config.get("networks", {}).items()
            if n.get("firewall_zone_id") in zones]


class AppUsage:
    """Zählt Bytes je (Netzwerk, App) pro Tag aus den Flows der gewählten Netze."""

    def __init__(self, coordinator: UniFiCoordinator, network_ids: list[str] | None) -> None:
        self.coordinator = coordinator
        self._configured = network_ids
        self._last_poll = 0.0
        self._last_ts = int(time.time() * 1000) - APP_POLL_S * 1000
        self._date = dt_util.now().date()
        self._flow_bytes: dict[str, tuple[str, str, int]] = {}  # flow-id -> (net, app, bytes)
        self.error: str | None = None

    def _roll(self) -> None:
        today = dt_util.now().date()
        if today != self._date:
            self._date = today
            self._flow_bytes.clear()

    @property
    def network_ids(self) -> set[str]:
        if self._configured is not None:
            data = self.coordinator.data
            if not data:
                return set(self._configured)
            # Optionen können noch alte IDs (vor Network 11) enthalten
            return {data.real_id("networks", n) or n for n in self._configured}
        return set(default_kid_networks(self.coordinator))

    async def async_poll(self) -> None:
        if not self.network_ids or time.monotonic() - self._last_poll < APP_POLL_S:
            return
        self._last_poll = time.monotonic()
        self._roll()
        now = int(time.time() * 1000)
        try:
            flows = await async_fetch_flows(self.coordinator, self._last_ts - 60_000, now)
            self.error = None
        except UniFiApiError as err:
            if self.error != str(err):
                _LOGGER.warning("App-Nutzung: Flows nicht abrufbar: %s", err)
            self.error = str(err)
            return
        self._last_ts = now
        data = self.coordinator.data
        for f in flows:
            net = (f.get("source") or {}).get("network_id")
            if data and net:   # Flows können alte oder neue Netz-IDs liefern (Network 11)
                net = data.real_id("networks", net) or net
            if net not in self.network_ids:
                continue
            app = flow_app(f) or "Sonstiges"
            b = int((f.get("traffic_data") or {}).get("bytes_total") or 0)
            fid = f.get("id") or f"{f.get('time')}-{id(f)}"
            prev = self._flow_bytes.get(fid)
            if prev is None or b > prev[2]:
                self._flow_bytes[fid] = (net, app, b)

    def usage(self, network_id: str) -> dict[str, float]:
        """App -> MB heute für ein Netz (absteigend)."""
        self._roll()
        acc: dict[str, int] = defaultdict(int)
        for net, app, b in self._flow_bytes.values():
            if net == network_id:
                acc[app] += b
        return {a: round(v / 1_000_000, 1)
                for a, v in sorted(acc.items(), key=lambda i: -i[1])}
