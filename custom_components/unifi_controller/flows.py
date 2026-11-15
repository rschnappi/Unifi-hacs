"""Traffic-Flows: Abfrage/Diagnose, App-Erkennung über Domains, App-Nutzung pro Netz."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
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
    from .region import zone_of_network  # noqa: PLC0415

    return [nid for nid, n in data.config.get("networks", {}).items()
            if zone_of_network(data, n) in zones]


HISTORY_DAYS = 31          # so viele vergangene Tage bleiben gespeichert
BACKFILL_PAGES = 40        # erster Abruf nach Neustart ohne gespeicherten Tag: ab Mitternacht
NO_DOMAIN = "(ohne Domain)"


def base_domain(domain: str | None) -> str:
    """Domain auf die letzten beiden Teile kürzen (cdn.example.com → example.com)."""
    if not domain:
        return NO_DOMAIN
    parts = domain.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) > 1 else parts[0]


def _mb(acc: dict[str, int]) -> dict[str, float]:
    return {k: round(v / 1_000_000, 1) for k, v in sorted(acc.items(), key=lambda i: -i[1])}


class AppUsage:
    """Zählt Bytes je (Netzwerk, App) pro Tag aus den Flows der gewählten Netze.

    Der laufende Tag wird aus den einzelnen Flows gebildet (nach Flow-ID entdoppelt),
    abgeschlossene Tage werden je Netz als Summen gespeichert (HA-Storage, 31 Tage) –
    so gibt es neben „heute“ auch 7- und 30-Tage-Werte, auch über Neustarts hinweg.
    Für „Sonstiges“ wird zusätzlich die Domain mitgezählt (häufigste unerkannte Domains).
    """

    def __init__(self, coordinator: UniFiCoordinator, network_ids: list[str] | None) -> None:
        from homeassistant.helpers.storage import Store  # noqa: PLC0415

        from .const import DOMAIN  # noqa: PLC0415

        self.coordinator = coordinator
        self._configured = network_ids
        self._store: Store = Store(
            coordinator.hass, 1, f"{DOMAIN}.{coordinator.config_entry.entry_id}.app_usage")
        self._loaded = False
        self._last_poll = 0.0
        self._last_ts = int(time.time() * 1000) - APP_POLL_S * 1000
        self._date = dt_util.now().date()
        # flow-id -> (net, app, bytes, domain)
        self._flow_bytes: dict[str, tuple[str, str, int, str]] = {}
        # "YYYY-MM-DD" -> net -> {"apps": {app: bytes}, "unbekannt": {domain: bytes}}
        self._days: dict[str, dict[str, dict[str, dict[str, int]]]] = {}
        self.error: str | None = None

    # ---- Speichern / Laden -------------------------------------------------------------
    def _data(self) -> dict[str, Any]:
        return {"date": self._date.isoformat(), "last_ts": self._last_ts,
                "flows": {k: list(v) for k, v in self._flow_bytes.items()},
                "days": self._days}

    async def _async_load(self) -> None:
        self._loaded = True
        data = await self._store.async_load() or {}
        self._days = data.get("days") or {}
        today = dt_util.now().date()
        if data.get("date") == today.isoformat():
            self._flow_bytes = {k: tuple(v) for k, v in (data.get("flows") or {}).items()
                                if isinstance(v, list) and len(v) == 4}
            self._last_ts = int(data.get("last_ts") or self._last_ts)
        else:
            if data.get("date") and data.get("flows"):   # gespeicherter Vortag → abschließen
                self._date = dt_util.parse_date(data["date"]) or today
                self._flow_bytes = {k: tuple(v) for k, v in data["flows"].items()
                                    if isinstance(v, list) and len(v) == 4}
                self._close_day()
            self._date = today
            self._flow_bytes = {}
            self._last_ts = int(dt_util.start_of_local_day().timestamp() * 1000)
        self._prune()

    def _save(self) -> None:
        self._store.async_delay_save(self._data, 30)

    # ---- Tageswechsel ------------------------------------------------------------------
    def _totals(self) -> dict[str, dict[str, dict[str, int]]]:
        out: dict[str, dict[str, dict[str, int]]] = {}
        for net, app, b, dom in self._flow_bytes.values():
            n = out.setdefault(net, {"apps": defaultdict(int), "unbekannt": defaultdict(int)})
            n["apps"][app] += b
            if app == "Sonstiges":
                n["unbekannt"][dom] += b
        return {net: {k: dict(v) for k, v in d.items()} for net, d in out.items()}

    def _close_day(self) -> None:
        if self._flow_bytes:
            self._days[self._date.isoformat()] = self._totals()

    def _prune(self) -> None:
        oldest = (dt_util.now().date() - timedelta(days=HISTORY_DAYS)).isoformat()
        for d in [d for d in self._days if d < oldest]:
            del self._days[d]

    def _roll(self) -> None:
        today = dt_util.now().date()
        if today != self._date:
            self._close_day()
            self._date = today
            self._flow_bytes.clear()
            self._prune()
            self._save()

    @property
    def network_ids(self) -> set[str]:
        if self._configured is not None:
            return set(self._configured)
        return set(default_kid_networks(self.coordinator))

    async def async_poll(self) -> None:
        if not self.network_ids or time.monotonic() - self._last_poll < APP_POLL_S:
            return
        backfill = not self._loaded
        if not self._loaded:
            await self._async_load()
        self._last_poll = time.monotonic()
        self._roll()
        now = int(time.time() * 1000)
        try:
            flows = await async_fetch_flows(
                self.coordinator, self._last_ts - 60_000, now,
                max_pages=BACKFILL_PAGES if backfill else MAX_PAGES)
            self.error = None
        except UniFiApiError as err:
            if self.error != str(err):
                _LOGGER.warning("App-Nutzung: Flows nicht abrufbar: %s", err)
            self.error = str(err)
            return
        self._last_ts = now
        day_start = int(dt_util.start_of_local_day().timestamp() * 1000)
        for f in flows:
            net = (f.get("source") or {}).get("network_id")
            if net not in self.network_ids or (f.get("time") or now) < day_start:
                continue
            app = flow_app(f) or "Sonstiges"
            dom = base_domain(((f.get("destination") or {}).get("domains") or [None])[0])
            b = int((f.get("traffic_data") or {}).get("bytes_total") or 0)
            fid = f.get("id") or f"{f.get('time')}-{id(f)}"
            prev = self._flow_bytes.get(fid)
            if prev is None or b > prev[2]:
                self._flow_bytes[fid] = (net, app, b, dom)
        self._save()

    # ---- Auswertung --------------------------------------------------------------------
    def _collect(self, network_id: str, days: int, key: str) -> dict[str, int]:
        self._roll()
        acc: dict[str, int] = defaultdict(int)
        for net, app, b, dom in self._flow_bytes.values():
            if net == network_id:
                if key == "apps":
                    acc[app] += b
                elif app == "Sonstiges":
                    acc[dom] += b
        if days > 1:
            first = (self._date - timedelta(days=days - 1)).isoformat()
            for d, nets in self._days.items():
                if d >= first:
                    for k, v in ((nets.get(network_id) or {}).get(key) or {}).items():
                        acc[k] += int(v)
        return acc

    def usage(self, network_id: str, days: int = 1) -> dict[str, float]:
        """App -> MB für ein Netz: heute (days=1) bzw. die letzten N Tage inkl. heute."""
        return _mb(self._collect(network_id, days, "apps"))

    def unknown_domains(self, network_id: str, days: int = 1, top: int = 15) -> dict[str, float]:
        """Häufigste Domains hinter „Sonstiges“ (MB), damit die App-Liste ergänzt werden kann."""
        return dict(list(_mb(self._collect(network_id, days, "unbekannt")).items())[:top])

    def days_with_data(self, network_id: str, days: int) -> int:
        first = (self._date - timedelta(days=days - 1)).isoformat()
        past = sum(1 for d, nets in self._days.items() if d >= first and network_id in nets)
        today = any(v[0] == network_id for v in self._flow_bytes.values())
        return past + int(today)
