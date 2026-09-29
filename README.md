# UniFi Controller Manager

Home-Assistant-Integration, die einen **UniFi Network Controller komplett** in Home Assistant bringt:
Netzwerke/VLANs, WLANs, zonenbasierte Firewall, VPN, Traffic-Regeln, Portweiterleitungen, DNS,
Geräte, Clients – plus das **System-Log** des Controllers, ein eingebautes **Fail2Ban** und **Länder-Blocking**.
Zugriff ausschließlich über den offiziellen **API-Key** von UniFi OS, keine Benutzer/Passwort-Anmeldung,
keine externen Python-Abhängigkeiten.

[![Open in HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=rschnappi&repository=Unifi-hacs&category=integration)
[![Integration hinzufügen](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=unifi_controller)

Getestet mit UDM Pro SE, UniFi OS 5 / Network 10.6. Sollte mit allen UniFi-OS-Konsolen
(UDM, UCG, UDR, UX, Cloud Key Gen2+) ab Network 9 funktionieren.

## Was die Integration kann

| Bereich | In Home Assistant |
| --- | --- |
| Controller | Internet-Status, WAN-IP, Download/Upload, Latenz, Status je Subsystem (WAN/LAN/WLAN/WWW/VPN), Client-Zähler |
| Netzwerke / VLANs | Netz ein/aus, Internetzugang ein/aus, Clients pro Netz (VLAN, Subnetz, DHCP als Attribute) |
| VPN | WireGuard/OpenVPN-Server und -Clients ein/aus, Clients, **Serverschlüssel neu erzeugen** |
| Firewall | jede eigene Zonen-Policy als Schalter (Quell-/Zielzone, IPs, Ports als Attribute) |
| Traffic / QoS | Traffic-Regeln, Traffic-Routen, QoS-Regeln als Schalter |
| Sonstiges | Portweiterleitungen, statische Routen, DNS-Einträge, WLANs (inkl. Passwort neu erzeugen) |
| Geräte | Online, Status, Firmware-Update, CPU, Speicher, Temperatur, Clients, IP, LED, Neustart, PoE, Power-Cycle |
| Clients | sperren/entsperren, trennen, vergessen, Gast freigeben – optional als Schalter |
| Logs | System-Log als Logbuch-Einträge, Tageszähler, letzte Sicherheitsmeldung, Events, optional Log-Datei |
| Fail2Ban | auffällige öffentliche IPs automatisch in eine UniFi-Adressgruppe → Firewall blockt (IPS-Treffer sofort, HA-Login-Fehlversuche mit Schwelle) |
| Länder-Blocking | UniFi Region Blocking mit Länderauswahl in den Optionen |
| Alles andere | generische Services zum Lesen/Ändern/Anlegen/Löschen jedes Config-Objekts + roher API-Zugriff |

Neue Objekte (Policy angelegt, VLAN dazu, neuer AP …) erscheinen automatisch, gelöschte werden unavailable.

## Installation

**HACS:** HACS → ⋮ → *Benutzerdefinierte Repositories* → `https://github.com/rschnappi/Unifi-hacs`,
Kategorie *Integration* → installieren → HA neu starten.
**Manuell:** `unifi_controller.zip` aus dem neuesten [Release](https://github.com/rschnappi/Unifi-hacs/releases/latest)
nach `/config/custom_components/unifi_controller/` entpacken, neu starten.

### API-Key erstellen

UniFi Network → *Einstellungen → Control Plane → Integrationen* → **API-Key erstellen**.
Der Key braucht Admin-Rechte auf der Site, sonst sind Firewall-, VPN- und Netzwerk-Änderungen nicht möglich.

### Einrichten

*Einstellungen → Geräte & Dienste → Integration hinzufügen → UniFi Controller Manager*

| Feld | Bedeutung |
| --- | --- |
| Host | IP oder Hostname der Konsole, z. B. `192.168.1.1` |
| Site | meist `default` |
| API-Key | direkt eintragen … |
| *oder* secrets.yaml-Eintrag | … oder nur den **Namen** eines Eintrags in `secrets.yaml` (z. B. `unifi_api_key`) – dann wird der Key bei jedem Start frisch gelesen und nie in HA gespeichert |
| SSL prüfen | aus lassen bei selbstsigniertem Zertifikat der Konsole |

Host, Site oder Key später ändern: Integration → ⋮ → **Neu konfigurieren** (leeres Key-Feld = bisherigen behalten).
Wird der Key abgelehnt, startet HA automatisch den Dialog *API-Key erneuern*.

### Optionen (*Konfigurieren*)

Drei Bereiche: **Allgemein & Schalter**, **Logs & Fail2Ban**, **Länder-Blocking**.

| Option (Allgemein) | Standard | |
| --- | --- | --- |
| Namenspräfix | `Netz` | ergibt Gerätenamen wie `Netz UniFi`, `Netz Access Point Küche` |
| Abfrageintervall Statistik/Logs | 30 s | Geräte, Clients, WAN, System-Log |
| Abfrageintervall Konfiguration | 120 s | Netze, Policies, WLANs … – nach jedem Schreibzugriff sofort |
| Schalter anlegen für | alle | welche Objektgruppen als Schalter erscheinen |
| Sperr-Schalter für benannte Clients | aus | ein Schalter pro Client mit Namen |

## Entities

Mit Präfix `Netz` (Beispiele aus einer echten Installation):

| Entity | Inhalt |
| --- | --- |
| `binary_sensor.netz_unifi_internet` | Internet erreichbar |
| `sensor.netz_unifi_wan_ip` / `_wan_download` / `_wan_upload` / `_wan_latenz` | WAN |
| `sensor.netz_unifi_status_wan` / `_lan` / `_wlan` / `_www` / `_vpn` | Health je Subsystem (`ok`/`warning`/`error`) |
| `sensor.netz_unifi_clients_online` / `_wlan` / `_lan` / `_gaste` | Client-Zähler |
| `switch.netz_unifi_netzwerk_<netz>` | Netz/VLAN aktiv (Default-Netz ausgenommen) |
| `switch.netz_unifi_netzwerk_<netz>_internet` | Internetzugang des Netzes |
| `sensor.netz_unifi_netzwerk_<netz>_clients` | Clients im Netz, VLAN/Subnetz/DHCP als Attribute |
| `switch.netz_unifi_vpn_<vpn>` / `sensor.netz_unifi_vpn_<vpn>_clients` | VPN |
| `button.netz_unifi_vpn_<vpn>_schlussel_neu_erzeugen` | neuen WireGuard-Serverschlüssel erzeugen |
| `switch.netz_unifi_fw_<policy>` | eigene Firewall-Policy (vordefinierte werden ausgeblendet) |
| `switch.netz_unifi_traffic_regel_<name>` / `_traffic_route_<name>` / `_qos_<name>` | Traffic & QoS |
| `switch.netz_unifi_portweiterleitung_<name>` / `_route_<name>` / `_dns_<name>` | Portweiterleitung, Route, DNS |
| `switch.netz_unifi_wlan_<ssid>` | WLAN ein/aus |
| `button.netz_unifi_wlan_<ssid>_passwort_neu_erzeugen` | *(deaktiviert)* zufälliges WLAN-Passwort |
| `binary_sensor.netz_<gerät>_online`, `sensor.netz_<gerät>_status` | Gerät erreichbar / Detailstatus (verbunden, provisionierung, update …) |
| `sensor.netz_<gerät>_cpu` / `_speicher` / `_temperatur` / `_clients` / `_firmware` / `_ip` / `_gestartet` | Gerätewerte |
| `switch.netz_<gerät>_led`, `button.netz_<gerät>_neustart` | LED, Neustart |
| `switch.netz_<gerät>_port_<n>_poe`, `button.netz_<gerät>_port_<n>_power_cycle` | *(deaktiviert)* PoE je Port |

Logs, Fail2Ban und Länder-Blocking: siehe unten.

Passwörter, Schlüssel, PSKs, Tokens und Zertifikate (`x_*`-Felder und alles mit key/psk/token/secret/password/certificate
im Namen) tauchen **nie** in Attributen, Diagnosen oder Service-Antworten auf – außer man fordert sie mit
`include_secrets: true` ausdrücklich an.

## Services

| Service | Zweck |
| --- | --- |
| `unifi_controller.get_objects` | alle Objekte einer Ressource lesen (optional `filter`, `refresh`) |
| `unifi_controller.update_object` | Felder eines Objekts ändern, Rest bleibt erhalten |
| `unifi_controller.set_enabled` | Objekt aktivieren/deaktivieren |
| `unifi_controller.create_object` / `delete_object` | anlegen / löschen |
| `unifi_controller.get_logs` | System-Log abfragen (`hours`, `category`, `filter`) |
| `unifi_controller.ban_ip` / `unban_ip` / `get_bans` | Fail2Ban manuell |
| `unifi_controller.set_region_blocking` | Länder-Blocking setzen/ergänzen |
| `unifi_controller.regenerate_vpn_key` | neuen WireGuard-Serverschlüssel in HA erzeugen und setzen |
| `unifi_controller.regenerate_wlan_password` | zufälliges WLAN-Passwort setzen |
| `unifi_controller.block_client` / `unblock_client` / `reconnect_client` / `forget_client` | Clients |
| `unifi_controller.authorize_guest` / `unauthorize_guest` | Hotspot-Gäste |
| `unifi_controller.restart_device` / `power_cycle_port` | Geräte |
| `unifi_controller.set_wlan` | WLAN ein/aus, Passwort setzen |
| `unifi_controller.refresh` | Konfiguration sofort neu laden |
| `unifi_controller.api_request` | roher API-Zugriff für alles, was nicht abgedeckt ist |

Ressourcen: `networks`, `wlans`, `firewall_policies`, `firewall_zones`, `firewall_groups`,
`trafficrules`, `trafficroutes`, `portforwards`, `routes`, `dns_records`, `port_profiles`,
`usergroups`, `qos_rules`, `settings`, `users`. Objekte werden per **Name** oder `_id` angesprochen.
Fehlgeschlagene Service-Aufrufe landen mit der Controller-Antwort im HA-Log.

```yaml
# Kind sperren: Policy einschalten
action: unifi_controller.set_enabled
data: {resource: firewall_policies, object: Sperre Benjamin Internet, enabled: true}

# Internetzugang eines VLANs abdrehen
action: unifi_controller.update_object
data: {resource: networks, object: IoT, changes: {internet_access_enabled: false}}

# DNS-Eintrag anlegen
action: unifi_controller.create_object
data: {resource: dns_records, data: {key: nas.lan, record_type: A, value: 192.168.1.5, enabled: true}}

# IPS-Treffer der letzten 24 Stunden
action: unifi_controller.get_logs
data: {hours: 24, category: SECURITY, filter: intrusion}
response_variable: log

# alles andere – Pfade relativ zu /api/s/<site>/, v2/… für die v2-API, integration/… für die offizielle
action: unifi_controller.api_request
data: {method: GET, path: v2/firewall/zone}
response_variable: zones
```

## Logs & Fail2Ban

Das System-Log des Controllers (UniFi → *Insights/System Log*: Firewall-Blocks, IPS/Threats,
Admin-Anmeldungen, Client-Verbindungen, VPN, Updates …) wird bei jedem Abfragezyklus übernommen.

### Wo sehe ich was?

| Frage | Entity |
| --- | --- |
| Läuft Fail2Ban? Mit welchen Regeln? | `binary_sensor.netz_unifi_fail2ban_aktiv` (Regeln als Attribute) |
| Wer ist gerade gesperrt? | `sensor.netz_unifi_fail2ban_gesperrt` (Liste mit Grund und Ablauf) |
| Wer wurde zuletzt gesperrt? | `sensor.netz_unifi_fail2ban_letzte_sperre` |
| Was war der letzte Angriff? | `sensor.netz_unifi_letzte_sicherheitsmeldung` (Klartext, Details als Attribute) |
| Wie viel ist heute passiert? | `sensor.netz_unifi_ips_angriffe_heute`, `…_firewall_blocks_heute`, `…_security_events_heute`, `…_ha_login_fehlversuche_heute`, `…_fail2ban_sperren_heute`, `…_log_eintrage_heute` |
| Verlauf mit Text | **Logbuch** – „UniFi HIGH THREAT_BLOCKED: A network intrusion attempt from … [IP]“ und „UniFi Fail2Ban hat … gesperrt“ |
| Automationen | `event.netz_unifi_sicherheit` (nur sicherheitsrelevant), `event.netz_unifi_log` (alles), `event.netz_unifi_fail2ban`; Bus-Events `unifi_controller_alert`, `unifi_controller_log`, `unifi_controller_ban` |

„Sicherheitsrelevant“ = IPS-Treffer, Admin-Ereignisse, HA-Login-Fehlversuche und Security-Events mit
öffentlicher Quell-IP. `event.netz_unifi_log` feuert bei **jedem** Eintrag (auch interne Firewall-Blocks aus dem
IoT-Netz) – dort steht in der Aktivitätsanzeige nur der Zeitpunkt; den Inhalt zeigen Logbuch und Sensoren.

**Log-Datei** (Option, z. B. `/share/unifi/unifi.log`, rotiert bei 5 MB × 3), eine Zeile pro Ereignis:
```
2026-09-29T08:15:05+00:00 [MEDIUM] SECURITY BLOCKED_BY_FIREWALL src=203.0.113.5 dst=192.168.1.1 policy="IoT -> Gateway blocken" msg="…"
```
→ für ein externes fail2ban: `failregex = ^\S+ \[\w+\] SECURITY \S+ src=<HOST> `

### Eingebautes Fail2Ban

In den Optionen *Logs & Fail2Ban* einschalten:

| Option | Standard | |
| --- | --- | --- |
| Treffer bis zur Sperre (`maxretry`) | 5 | |
| Zeitfenster (`findtime`) | 600 s | |
| Sperrdauer (`bantime`) | 60 min | 0 = dauerhaft |
| Kategorien | `SECURITY` | kommagetrennt, z. B. `SECURITY,ADMIN` |
| Sofort sperren bei Events | `THREAT_BLOCKED,THREAT_DETECTED` | IPS-Treffer → Sperre schon beim 1. Mal |
| HA-Login-Fehlversuche mitzählen | an | fehlgeschlagene HA-Anmeldungen (echte Quell-IP via Portweiterleitung) |
| Nie sperren | – | IPs/Netze, kommagetrennt |
| Adressgruppe | `HA Fail2Ban` | wird bei der ersten Sperre angelegt |

Öffentliche Quell-IPs, die innerhalb von `findtime` `maxretry`-mal auftauchen (bzw. einmal bei Sofort-Events),
landen für `bantime` in der UniFi-**Adressgruppe**; nach Ablauf werden sie automatisch entfernt
(übersteht HA-Neustarts). Private Adressen und die Whitelist werden nie gesperrt.

**Einmalig nötig:** eine Firewall-Policy, die diese Gruppe blockt – je Zielzone, die von außen erreichbar ist:

| Name | Quelle | Ziel | Aktion |
| --- | --- | --- | --- |
| Fail2Ban External → Gateway | Zone *External*, IP-Gruppe *HA Fail2Ban* | Zone *Gateway* | Blocken |
| Fail2Ban External → *Zone mit Portweiterleitung* | Zone *External*, IP-Gruppe *HA Fail2Ban* | z. B. *IoT* | Blocken |

Leere Gruppen lehnt UniFi ab – solange niemand gesperrt ist, steht der Platzhalter `192.0.2.1`
(TEST-NET, nie im Internet geroutet) darin.

## Länder-Blocking

*Konfigurieren → Länder-Blocking*: Ein/Aus, Modus (**ausgewählte Länder sperren** oder **nur ausgewählte
Länder erlauben**), Richtung (ein-/ausgehend/beides) und Länderauswahl aus allen ISO-Ländern (deutsche Namen).
Die Einstellung wird direkt im Controller gespeichert (UniFi *Region Blocking*, Setting `usg_geo`) –
dieselbe Einstellung wie im UniFi-UI.

| Entity | Inhalt |
| --- | --- |
| `switch.netz_unifi_lander_blocking` | Länder-Blocking ein/aus |
| `sensor.netz_unifi_lander_blocking_lander` | Anzahl Länder, Liste als Attribut |

```yaml
action: unifi_controller.set_region_blocking
data: {enabled: true, action: block, traffic_direction: both, add: [CN, RU, KP, IR]}
```

## Migration von „UniFi Network Rules“

Die Integration deckt alles ab, was UniFi Network Rules bietet (Firewall-Policies, Traffic-Regeln/-Routen,
Portweiterleitungen, QoS, VPN, WLANs, LEDs). Umstieg:

1. UniFi Controller Manager einrichten – beide laufen parallel, die Entity-IDs kollidieren nicht
   (`switch.netz_fw_…` → `switch.netz_unifi_fw_…`)
2. Automationen, Skripte und Dashboards auf die neuen Entities umstellen
3. UniFi Network Rules deaktivieren, ein paar Tage beobachten, dann entfernen

## Releases

Ein neuer Release braucht **nur einen Tag** – die Version in `manifest.json` muss nicht angepasst werden:

```bash
git tag v0.4.0 && git push --tags
```

oder auf GitHub *Releases → Draft a new release → neuen Tag eintippen → Publish*.
Der Workflow schreibt die Version aus dem Tag in `manifest.json`, baut `unifi_controller.zip`
(das installiert HACS), und erzeugt die Release-Notes aus den Commit-Nachrichten seit dem letzten Tag.

## Hinweise

- **Gerät kurz „provisionierung“**: nach Änderungen an Netzen/Firewall übernimmt die Konsole die
  Konfiguration ein paar Sekunden lang. `…_online` bleibt dabei an, `…_status` zeigt es an.
- **Datasets, die ein Controller nicht kennt** (z. B. ältere Firmware ohne QoS), werden einmal als
  Warnung geloggt und dann ignoriert.
- **Diagnose** (*Integration → ⋮ → Diagnose herunterladen*) enthält Zähler je Dataset, fehlgeschlagene
  Datasets und geschwärzte Beispieldaten.
