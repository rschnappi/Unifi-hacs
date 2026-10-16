# Offizielle UniFi Network API

Ab Network 9 hat UniFi eine offizielle, dokumentierte API (`/proxy/network/integration/v1`).
Geprüft gegen **UniFi Network API 11.0.89**. Die Integration nutzt sie zusätzlich zur internen
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

## Was bewusst bei der internen API bleibt

Netze, WLANs, Firewall-Policies und -Zonen, DNS-Einträge, Traffic-Regeln, Portweiterleitungen,
Clients und Geräte laufen weiter über die interne API. Die offizielle API kann das inzwischen
großteils auch, verlangt beim Ändern aber jeweils das vollständige Objekt in einem anderen Schema.
Ein Umbau brächte kein neues Verhalten, nur Risiko. Die interne API funktioniert unter
Network 11 unverändert.
