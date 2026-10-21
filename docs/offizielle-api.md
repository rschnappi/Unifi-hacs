# Offizielle UniFi Network API

Ab Network 9 hat UniFi eine offizielle, dokumentierte API (`/proxy/network/integration/v1`).
Geprüft gegen **UniFi Network API 11.0.94** (vorher 11.0.89: gleiche 72 Endpunkte, gleiche Geräte-/Port-/Client-Aktionen, alle genutzten Felder unverändert). Die Integration nutzt sie zusätzlich zur internen
Legacy-/v2-API, und zwar dort, wo sie mehr kann. Ohne diese API (ältere Controller) läuft alles
wie bisher weiter.

## Neu in der Integration

| Funktion | Art | Endpunkt |
|---|---|---|
| Hotspot-Gutscheine erzeugen / abfragen / löschen | Dienste `create_vouchers`, `get_vouchers`, `delete_vouchers` | `hotspot/vouchers` |
| Gültige Gutscheine | Sensor *Hotspot-Gutscheine* (Codes, in Benutzung, abgelaufen) | `hotspot/vouchers` |
| Geräte zur Übernahme | Sensor *Geräte zur Übernahme*, Event + Benachrichtigung (Kategorie *Neue Geräte*) | `pending-devices` |
| Gerät übernehmen | Dienst `adopt_device` | `POST devices` |
| Live-Statistik eines Geräts (CPU, RAM, Last, Uplink, Funk) | Dienst `device_statistics` | `devices/{id}/statistics/latest` |
| Syslog-Logging / Flow-Reporting einer Firewall-Policy | Dienst `set_firewall_logging` | `PATCH firewall/policies/{id}` |
| Switch-ACL-Regeln | Schalter *ACL &lt;Name&gt;*, Dienst `set_acl_rule` | `acl-rules` |
| Weitere Ressourcen lesen | `get_objects` mit `resource` = `wans`, `vpn_servers`, `site_to_site_tunnels`, `radius_profiles`, `device_tags`, `dns_policies`, `traffic_matching_lists`, `switch_stacks`, `lags`, `mc_lag_domains`, `wifi_broadcasts`, `int_*` … und optional `api_filter` | diverse |

## Roher Zugriff

`api_request` kennt jetzt `PATCH`. In Pfaden `integration/…` wird `{site}` automatisch durch die
Site-UUID ersetzt:

```yaml
action: unifi_controller.api_request
data:
  method: GET
  path: integration/sites/{site}/firewall/policies?filter=metadata.origin.eq('USER_DEFINED')
response_variable: r
```

Filter-Syntax der offiziellen API: `name.like('IoT*')`, `expired.eq(false)`,
`and(enabled.eq(true), name.like('Gast*'))`, `not(...)`. Listen werden automatisch über alle
Seiten geladen.

## Umstellung auf die offizielle API

| Stufe | Bereich | Stand |
|---|---|---|
| 1 | Firewall-Policies, Zonen, Adresslisten (Traffic Matching Lists): Schalter, Länder-Blocking, Fail2Ban-Liste, Sperren der Kinderprofile, Länderliste | **umgestellt** |
| 2a | DNS-Einträge → DNS Policies (A, AAAA, CNAME, MX, TXT, SRV, Forward): Schalter je Eintrag, Dienste `set_dns_record` / `delete_dns_record` | **umgestellt** |
| 2b | Netze und WLANs schreiben: Netz-, Internet- und VPN-freie LAN-Schalter, WLAN-Schalter, `set_wlan` (aktiv, versteckt, Client-Isolation) über `networks` bzw. `wifi/broadcasts`; Zuordnung über die `external_id` | **umgestellt** |
| 3 | Geräte- und Client-Aktionen: Neustart (Button/`restart_device`), PoE-Port (Button/`power_cycle_port`), Gast freigeben/sperren (`authorize_guest` neu mit Datenlimit und Bandbreite, `unauthorize_guest`) über `devices/{id}/actions`, `…/ports/{idx}/actions`, `clients/{id}/actions` | **umgestellt** |

Ab 11.0.94 liefert das offizielle Netz-Detail auch `ipv4Configuration` (Gateway-IP, Präfix,
DHCP-Modus, -Bereich, Lease-Zeit, Domain) und `cellularBackupEnabled`. Die Integration liest das
für Gateway-Netze alle 15 min (max. 4 Abrufe parallel), ergänzt damit fehlende interne Felder und
zeigt DHCP-Modus, Lease-Zeit, Auto-Scale, Ping-Konfliktprüfung und Mobilfunk-Backup als Attribute
am Netz-Sensor.

Gelesen werden Netze und WLANs sonst weiter intern: WAN- und VPN-Netze,
WLAN-Passwörter und die Netz-IDs, auf die sich die Clients beziehen, liefert nur die interne API.
Geschrieben wird offiziell, sobald alle geänderten Felder dort ein Gegenstück haben
(`enabled`, `name`, `vlanId`, `internetAccessEnabled`, `isolationEnabled`,
`mdnsForwardingEnabled`, `hideName`, `clientIsolationEnabled`): Detail-Objekt lesen, Änderung
einsetzen, PUT. Ohne offizielle API (ältere Controller) fällt die Integration auf die interne
zurück. Intern bleiben WLAN-Passwort, WireGuard-Schlüssel, VPN/WAN und das Anlegen der
Kinderprofil-Netze (das offizielle Anlage-Schema für Gateway-Netze ist nicht dokumentiert).

## Was intern bleiben muss

Für folgende Bereiche hat die offizielle API (11.0.94) keine Endpunkte: Traffic-Regeln und
-Routen (App-Sperren), Portweiterleitungen, statische Routen, QoS, Port-Profile, bekannte
Clients (Netz-Zuordnung, Sperren), WireGuard-Zugänge, System-Log, Flows, Speedtest, Backups,
LED/Locate und die Live-Statistik (Signal, AP, Temperaturen, Portfehler, Durchsatz).
