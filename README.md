# UniFi Controller Manager

Home-Assistant-Integration (HACS) zur Verwaltung eines UniFi Network Controllers (UniFi OS: UDM/UCG/UDR/Cloud Key Gen2+) über einen **API-Key**.
Der Key wird zur Laufzeit aus `secrets.yaml` gelesen und **nie** im Config-Entry gespeichert.

## Installation
1. HACS → Benutzerdefinierte Repositories → dieses Repo (Typ *Integration*)
2. „UniFi Controller Manager“ installieren, HA neu starten
3. In `secrets.yaml`: `unifi_api_key: "<key>"` (UniFi → Einstellungen → Control Plane → Integrationen → API-Key)
4. Einstellungen → Geräte & Dienste → Integration hinzufügen → *UniFi Controller Manager*

Key-Rotation: neuen Key in `secrets.yaml` eintragen, Integration neu laden.

## Entitäten
| Bereich | Entitäten |
|---|---|
| Controller | Internet, WAN IP/Download/Upload/Latenz, Status je Subsystem (WAN/LAN/WLAN/WWW/VPN), Clients online/WLAN/LAN/Gäste, Version |
| WLANs | Schalter je WLAN |
| Geräte | Online, Firmware-Update, CPU, Speicher, Temperatur, Clients, Durchsatz, Gestartet, Firmware, IP, LED, Lokalisieren*, Neustart |
| Switch-Ports | PoE-Schalter*, Power-Cycle-Button* |
| Optional | Client-Sperre (benannte Clients), Portweiterleitungen, Traffic-Regeln, Firewall-Policies (Zonen-FW) |

\* standardmäßig deaktiviert. Neue Geräte/WLANs/Regeln erscheinen automatisch.

## Services
`unifi_controller.api_request` (mit Response) für **jeden** API-Endpunkt:
```yaml
action: unifi_controller.api_request
data:
  method: GET
  path: rest/networkconf        # Legacy: /api/s/<site>/…
  # path: v2/firewall-zones     # v2-API
  # path: integration/sites     # offizielle Integration-API
response_variable: result
```
Außerdem: `block_client`, `unblock_client`, `reconnect_client`, `authorize_guest`, `restart_device`, `power_cycle_port`, `set_wlan` (aktivieren/deaktivieren/Passwort).

## Optionen
Namenspräfix (Standard `Netz`), Abfrageintervall, optionale Kategorien.
