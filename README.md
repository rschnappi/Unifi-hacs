# UniFi Controller Manager

Home-Assistant-Integration (HACS) zur **vollständigen** Verwaltung eines UniFi Network Controllers (UniFi OS: UDM/UCG/UDR/Cloud Key Gen2+, Network 9+/10+ mit zonenbasierter Firewall) über einen **API-Key**.
Der Key wird zur Laufzeit aus `secrets.yaml` gelesen und **nie** im Config-Entry gespeichert. Passwörter/Keys (`x_*`-Felder) landen weder in Attributen noch in Service-Antworten (außer mit `include_secrets: true`).

## Installation
1. HACS → Benutzerdefinierte Repositories → dieses Repo (Typ *Integration*)
2. „UniFi Controller Manager“ installieren, HA neu starten
3. `secrets.yaml`: `unifi_api_key: "<key>"` (UniFi → Einstellungen → Control Plane → Integrationen)
4. Geräte & Dienste → Integration hinzufügen → *UniFi Controller Manager*

## Entitäten
| Bereich | Entitäten |
|---|---|
| Controller | Internet, WAN IP/Download/Upload/Latenz, Status je Subsystem, Clients online/WLAN/LAN/Gäste, Version |
| Netzwerke/VLANs | Schalter *aktiv*, Schalter *Internetzugang*, Sensor *Clients* (VLAN, Subnetz, DHCP als Attribute) |
| VPN | Schalter je VPN-Server/-Client (WireGuard, OpenVPN, Site-to-Site), Sensor *Clients* |
| Firewall | Schalter je eigener Policy (Quell-/Zielzone, IPs, Ports als Attribute) |
| Traffic | Schalter je Traffic-Regel und Traffic-Route |
| Sonstiges | Portweiterleitungen, statische Routen, DNS-Einträge, WLANs |
| Geräte | Online, Firmware-Update, CPU, Speicher, Temperatur, Clients, IP, Neustart, LED, Lokalisieren*, PoE*, Power-Cycle* |

\* standardmäßig deaktiviert. Neue Objekte erscheinen automatisch; welche Schaltergruppen angelegt werden, ist in den Optionen wählbar.

## Services – alles steuerbar
Ressourcen: `networks`, `wlans`, `firewall_policies`, `firewall_zones`, `firewall_groups`, `trafficrules`, `trafficroutes`, `portforwards`, `routes`, `dns_records`, `port_profiles`, `usergroups`, `users`

```yaml
# lesen
action: unifi_controller.get_objects
data: {resource: firewall_policies, filter: Sperre}
response_variable: fw

# ändern (nur angegebene Felder, Rest bleibt erhalten)
action: unifi_controller.update_object
data:
  resource: networks
  object: IoT              # Name oder _id
  changes: {internet_access_enabled: false}

# aktivieren/deaktivieren
action: unifi_controller.set_enabled
data: {resource: firewall_policies, object: Sperre Benjamin Internet, enabled: true}

# anlegen / löschen
action: unifi_controller.create_object
data: {resource: dns_records, data: {key: nas.local, record_type: A, value: 192.168.10.5, enabled: true}}

# alles andere: roher API-Zugriff (Legacy, v2/…, integration/…)
action: unifi_controller.api_request
data: {method: GET, path: v2/firewall/zone}
response_variable: result
```
Außerdem: `block_client`, `unblock_client`, `reconnect_client`, `forget_client`, `authorize_guest`, `unauthorize_guest`, `restart_device`, `power_cycle_port`, `set_wlan`, `refresh`.

## Optionen
Namenspräfix (Standard `Netz`), Abfrageintervall Statistik (30 s) und Konfiguration (120 s; nach jedem Schreibzugriff sofort), Schaltergruppen, Client-Sperr-Schalter.
