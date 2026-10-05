# Entwicklungsablauf

Kurzfassung für alle, die am Code arbeiten (auch automatisiert):

1. **Nie direkt auf `main`** – Änderungen auf einen Branch `claude/<thema>` bzw. `<name>/<thema>` pushen.
2. Die Pipeline (`.github/workflows/ci.yml`) prüft jeden Push:
   ruff (Syntax/undefinierte Namen), JSON/YAML + Übersetzungen, **hassfest**, **HACS**, Importtest (Python 3.14).
3. Sind alle Prüfungen grün, legt die Pipeline **selbst den PR an, merged ihn per Squash** und löscht den Branch.
4. Aus `main` entsteht automatisch das **Release** (Tag + `unifi_controller.zip`).

## Versionssprung über die Commit-Nachricht

Der Squash-Titel ist die Nachricht des **letzten** Commits auf dem Branch:

| Nachricht | Sprung |
| --- | --- |
| `BREAKING` / `typ!:` | Major |
| `feat: …` oder `[minor]` | Minor |
| alles andere | Patch |
| `[skip release]` oder nur Doku/Workflows | kein Release |

## Größere Änderungen in mehreren Commits

Wer über mehrere Commits pusht, verhindert ein vorzeitiges Mergen mit einer absichtlich ungültigen Datei
(z. B. `custom_components/unifi_controller/_wip_marker.py` mit Syntaxfehler) und entfernt sie im
letzten Commit – mit der gewünschten Commit-Nachricht (`feat: …`).

## Voraussetzung im Repo

*Settings → Actions → General → Workflow permissions*: **Read and write permissions** und
**Allow GitHub Actions to create and approve pull requests**.
