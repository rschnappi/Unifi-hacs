# Anwesenheit

Personen werden unter *Geräte & Dienste → UniFi Controller → Person hinzufügen* angelegt
(Config-Subentry, wie Kinderprofile). Pro Person: Geräte (Handy, Uhr …), optional
Ausgangs-Access-Points, zwei Fristen und Zusatzquellen.

| Situation | Ergebnis |
|---|---|
| Gerät verbindet sich (Abruf oder Connect-Event) | **sofort** anwesend |
| Verbindung endet an einem Ausgangs-AP (z. B. Vorraum) | abwesend nach der **kurzen Frist** (Standard 3 min) |
| Verbindung endet an einem anderen AP (Handy schläft, WLAN im Doze) | abwesend erst nach der **langen Frist** (Standard 15 min) |
| kurzer Connect zwischen zwei Abrufen (Doze-Aufwachen) | Frist beginnt neu |
| Zusatzquelle meldet `home` / `on` | bleibt anwesend – abwesend nur, wenn **alle** Quellen zustimmen |
| HA-Neustart | `last_seen` aus dem Controller – laufende Fristen gehen nicht verloren |

**Entitäten** (Gerät „Person &lt;Name&gt;“):

| Entität | Inhalt |
|---|---|
| `binary_sensor.person_<name>_anwesend` | `presence`; Attribute *seit*, *grund*, *ausloeser*, je Gerät Zustand + Grund, Zusatzquellen |
| `sensor.person_<name>_raum` | HA-Bereich des AP, an dem das Handy hängt (sonst AP-Name); `Abwesend` |
| `device_tracker.<name>_<gerät>` | Router-Tracker je Gerät **mit denselben Fristen** – der HA-Person zuordnen |

Event `unifi_controller_presence` (`person`, `state: arrived|left`, `trigger`, `reason`, `room`)
für Automationen, dazu ein Logbuch-Eintrag. Benachrichtigungen über die Kategorie
*Anwesenheit* – nur wenn dort Empfänger gewählt sind.

Hinweise:
- **Raum:** den Access Points in HA einen Bereich zuweisen, dann zeigt der Raum-Sensor den Bereich.
- **Private MAC:** pro WLAN feste private Adressen funktionieren. Wechselt ein Gerät seine MAC
  regelmäßig, erkennt die Integration das (gleicher Hostname, neue MAC) und meldet es.
- **Kinder:** keine automatische Anwesenheit aus dem Kindernetz – dort hängen auch stationäre
  Geräte (PC, Konsole). Stattdessen das Kind als Person mit seinem Handy anlegen.
- Eigene Tracker dieser Integration sind als Zusatzquelle gesperrt (würden sich selbst bestätigen).
