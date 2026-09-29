# UniFi Controller Manager

Home-Assistant-Integration (HACS) zur **vollständigen** Verwaltung eines UniFi Network Controllers (UniFi OS: UDM/UCG/UDR/Cloud Key Gen2+, Network 9+/10+ mit zonenbasierter Firewall) über einen **API-Key**.
Ersetzt u. a. *UniFi Network Rules* (Firewall-Policies, Traffic-Regeln/-Routen, Portweiterleitungen, QoS, LEDs, VPN).

## Installation
1. HACS → Benutzerdefinierte Repositories → dieses Repo (Typ *Integration*)
2. „UniFi Controller Manager“ installieren, HA neu starten
3. Geräte & Dienste → Integration hinzufügen → *UniFi Controller Manager*
4. Host, Site und **API-Key** eintragen (UniFi → Einstellungen → Control Plane → Integrationen) – alternativ den Namen eines Eintrags in `secrets.yaml`

Host/Key später ändern: Integration → ⋮ → **Neu konfigurieren**.
Passwörter/Keys (`x_*`-Felder) landen weder in Attributen noch in Service-Antworten (außer `include_secrets: true`).

## Entitäten
| Bereich | Entitäten |
|---|---|
| Controller | Internet, WAN IP/Download/Upload/Latenz, Status je Subsystem, Clients online/WLAN/LAN/Gäste, Version |
| Netzwerke/VLANs | Schalter *aktiv* und *Internetzugang*, Sensor *Clients* |
| VPN | Schalter je VPN, Sensor *Clients*, Button **Schlüssel neu erzeugen** (WireGuard) |
| Firewall | Schalter je eigener Policy (Zonen, IPs, Ports als Attribute) |
| Traffic/QoS | Schalter je Traffic-Regel, Traffic-Route, QoS-Regel |
| Sonstiges | Portweiterleitungen, Routen, DNS-Einträge, WLANs (+ Button *Passwort neu erzeugen*, deaktiviert) |
| Geräte | Online, Firmware-Update, CPU, Speicher, Temperatur, Clients, IP, Neustart, LED, Lokalisieren*, PoE*, Power-Cycle* |
| Logs | Event-Entität **Log** (jeder System-Log-Eintrag), Event **Fail2Ban**, Sensor **Fail2Ban gesperrt** |

\* standardmäßig deaktiviert.

## Logs & Fail2Ban
Das UniFi-System-Log (Firewall-Blocks, IPS/Threats, Admin-Logins, Clients, VPN …) wird bei jedem Poll übernommen:
- HA-Event `unifi_controller_log` (category, event, severity, message, src_ip, dst_ip, client, policy …)
- Event-Entität `event.netz_unifi_log`
- optional Log-Datei (Option *Log-Datei*, z. B. `/share/unifi/unifi.log`), rotiert, eine Zeile pro Ereignis mit `src=<IP>` – direkt für ein externes fail2ban nutzbar

**Integriertes Fail2Ban** (Optionen → *Logs & Fail2Ban*): öffentliche Quell-IPs, die in `findtime` Sekunden `maxretry`-mal in den gewählten Kategorien auftauchen, landen für `bantime` Minuten in der UniFi-Adressgruppe *HA Fail2Ban*. Private IPs und die Whitelist werden nie gesperrt.
Die Gruppe muss von einer Firewall-Policy verwendet werden (Quelle: Zone External, IP-Gruppe *HA Fail2Ban*, Aktion Block).

## Services
| Service | Zweck |
|---|---|
| `get_objects` / `update_object` / `create_object` / `delete_object` / `set_enabled` | CRUD für `networks`, `wlans`, `firewall_policies`, `firewall_zones`, `firewall_groups`, `trafficrules`, `trafficroutes`, `portforwards`, `routes`, `dns_records`, `port_profiles`, `usergroups`, `qos_rules`, `users` |
| `get_logs` | System-Log abfragen (Stunden, Kategorie, Filter) |
| `ban_ip` / `unban_ip` / `get_bans` | Fail2Ban manuell |
| `regenerate_vpn_key` | neuen WireGuard-Serverschlüssel in HA erzeugen und setzen |
| `regenerate_wlan_password` | zufälliges WLAN-Passwort setzen |
| `api_request` | roher API-Zugriff (Legacy, `v2/…`, `integration/…`) |
| `block_client`, `unblock_client`, `reconnect_client`, `forget_client`, `authorize_guest`, `unauthorize_guest`, `restart_device`, `power_cycle_port`, `set_wlan`, `refresh` | Aktionen |

```yaml
action: unifi_controller.set_enabled
data: {resource: firewall_policies, object: Sperre Benjamin Internet, enabled: true}
```
