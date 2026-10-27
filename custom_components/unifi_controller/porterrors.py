"""Port-Fehlerzähler „zurücksetzen“.

UniFi zählt rx/tx-Fehler seit dem letzten Neustart des Geräts und bietet keinen Reset an.
Die Integration merkt sich deshalb je Port einen Ausgangswert (nach z. B. Kabeltausch) und
zeigt nur die Fehler seitdem. Sinkt der Rohzähler (Neustart), gilt automatisch 0 als Basis.
"""
from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import DOMAIN


class PortErrors:
    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        self._store: Store = Store(hass, 1, f"{DOMAIN}.{entry_id}.port_errors")
        self.base: dict[str, dict[str, dict[str, Any]]] = {}   # mac → port → {rx, tx, at}

    async def async_load(self) -> None:
        self.base = await self._store.async_load() or {}

    def adjusted(self, mac: str, port: dict) -> dict[str, Any]:
        """Fehler seit dem Zurücksetzen (bzw. seit Geräte-Neustart)."""
        b = self.base.get(mac.lower(), {}).get(str(port.get("port_idx")), {})
        raw_rx, raw_tx = int(port.get("rx_errors") or 0), int(port.get("tx_errors") or 0)
        rx_base, tx_base = int(b.get("rx", 0)), int(b.get("tx", 0))
        if b and (raw_rx < rx_base or raw_tx < tx_base):   # Gerät neu gestartet → ab 0
            b["rx"] = b["tx"] = 0
            rx_base = tx_base = 0
            self._store.async_delay_save(lambda: self.base, 2)
        return {"rx": raw_rx - rx_base, "tx": raw_tx - tx_base, "seit": b.get("at")}

    def reset(self, devices: dict[str, dict], mac: str | None = None,
              port: int | None = None) -> list[str]:
        """Aktuelle Rohzähler als neue Basis merken; liefert die betroffenen Ports."""
        now = dt_util.now().isoformat(timespec="seconds")
        done: list[str] = []
        for m, dev in devices.items():
            if mac and m.lower() != mac.lower():
                continue
            for p in dev.get("port_table") or []:
                if port is not None and p.get("port_idx") != port:
                    continue
                self.base.setdefault(m.lower(), {})[str(p.get("port_idx"))] = {
                    "rx": int(p.get("rx_errors") or 0), "tx": int(p.get("tx_errors") or 0),
                    "at": now}
                done.append(f"{dev.get('name') or m} Port {p.get('port_idx')}")
        self._store.async_delay_save(lambda: self.base, 2)
        return done
