# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

## [3.1.1] - 2026-03-17

### Verbesserungen

- **Dokumentation**
  - README vollständig überarbeitet und auf den aktuellen Stand gebracht
  - `config.py`-Beispiel in der README enthält jetzt alle Konstanten (inkl. WireGuard und Fail2Ban)
  - Neuer Konfigurations-Abschnitt für Fail2Ban-Pfadvariablen
  - Verzeichnis-Übersicht um Fail2Ban-Pfade erweitert
  - Fehlerbehebungs-Abschnitt für Fail2Ban ergänzt (`fail2ban-regex`, `fail2ban-client unbanip` etc.)
  - Lizenzanalyse aller verwendeten Komponenten dokumentiert

---

## [3.1.0] - 2026-03-17

### Hinzugefügt

- **Fail2Ban-Integration** (`nrp f2b`)
  - Neuer Command-Bereich `nrp f2b` zur Verwaltung der Fail2Ban-Integration
  - `nrp f2b enable` – installiert fail2ban falls nötig, schreibt Jail- und Filter-Konfigurationen, startet den Dienst
  - `nrp f2b enable --with-scanners` – aktiviert zusätzlich den `nginx-scanners`-Jail
  - `nrp f2b disable` – entfernt NRP-Konfiguration, fail2ban läuft weiter
  - `nrp f2b status` – zeigt aktive Jails und aktuell gebannte IPs

- **Aktivierte Jails (Standard)**
  - `nginx-http-auth` – Brute-Force auf HTTP-Authentifizierung
  - `nginx-botsearch` – Bot/Scanner-Erkennung (built-in Filter)
  - `nginx-404` – IP-Banning bei gehäuften 404-Fehlern (30 Treffer / 60 s → 12 h Ban)

- **Optionaler Scanner-Jail** (`--with-scanners`)
  - `nginx-scanners` – erkennt Scans auf WP-Login, phpMyAdmin, `.env`, `.git` u. Ä. (2 Treffer / 10 min → 24 h Ban)

- **Eigene Filter-Definitionen**
  - `nginx-404.conf` – benutzerdefinierter Filter für 404-basiertes Banning
  - `nginx-scanners.conf` – benutzerdefinierter Filter für Scanner-Erkennung

- **Neue Konfigurationskonstanten** in `config.py`
  - `F2B_JAIL_DIR`, `F2B_FILTER_DIR`, `F2B_NRP_JAIL_CONF`, `F2B_FILTER_404`, `F2B_FILTER_SCANNERS`

---

## [3.0.0] - 2026-03-17

### Hinzugefügt

- **WireGuard Site-Management** (`nrp site`)
  - Hub-and-Spoke-Tunnel-Architektur: VPS als Hub, beliebig viele Remote-Sites als Spokes
  - Dienste hinter NAT ohne Port-Forwarding veröffentlichen
  - Automatische Subnetz-Vergabe aus dem Overlay-Netzwerk `10.240.0.0/16`
  - `nrp site create` – neue Site anlegen, Subnetz-Größe über `--targets` oder `--subnet-prefix`
  - `nrp site list` – tabellarische Übersicht aller Sites
  - `nrp site show [--live]` – Detailansicht inkl. optionalem Ping-Test
  - `nrp site delete [--keep-config]` – Site entfernen
  - `nrp site install-script` – Bash-Installationsscript für den Remote-Host generieren
  - `nrp site set-pubkey` – Public Key des Remote-Hosts registrieren und `wg0.conf` aktualisieren
  - Optionale LAN-CIDR-Unterstützung (`--lan-cidr`) für Routing ins Heimnetz

- **Setup-Erweiterung**
  - `nrp setup --with-wireguard` – installiert WireGuard, aktiviert IP-Forwarding, initialisiert Hub-Interface `wg0`

- **Proxy-Host via Tunnel**
  - `nrp add --site <NAME>` – Upstream-IP wird gegen das Subnetz der Site validiert

- **Neue Konfigurationskonstanten** in `config.py`
  - `WG_OVERLAY_CIDR`, `WG_INTERFACE_NAME`, `WG_CONFIG_PATH`, `WG_PORT`
  - `NRP_DATA_DIR`, `SITES_DB_PATH`

---

## [2.3.0] - 2025-11-07

### Hinzugefügt

- **Proxy Buffering**
  - Request Buffering kann jetzt pro Host in den NGINX-Konfigurationen deaktiviert werden
  - Betrifft beide Templates: `nginx_standard.conf.j2` und `nginx_custom_port.conf.j2`
  - Sinnvoll für Streaming-Anwendungen und große File-Uploads

---

## [2.2.1] - 2025

### Bugfix

- **Shell-Completion**
Die Shell Completion führte zu Fehlern wegen eines falschen aufruf des python click Parameters.
  - Vorher (falsch):
    @click.argument('fqdn', autocompletion=complete_domains)

  - Jetzt (richtig):
    @click.argument('fqdn', shell_complete=complete_domains)

## [2.2.0] - 2025

### Hinzugefügt

- **Neue CLI-Befehle**
  - `nrp completion` - Hinzufügen von Shell completion für Befehle und Optionen

## [2.1.0] - 2025

### Hinzugefügt

- **Neue add Option**
  - `--full-interactive` - frägt bei einem reinen `nrp add` alle Optionen ab

- **Verbesserungen**
  - Symlink bei der Instalaltion für ein Ausführen des Tools ohne aktives venv 

### Verbeserungen
## [2.0.0] - 2025

### Hinzugefügt

- **Komplette Neuimplementierung in Python**
  - Modernes CLI-Tool mit Click Framework
  - Jinja2 Templates für flexible Konfigurationen
  - Automatische Input-Validierung (FQDN, IP, Ports)
  - Unit Tests mit pytest

- **Neue CLI-Befehle**
  - `nrp add` - Proxy-Host hinzufügen (interaktiv oder mit Parametern)
  - `nrp remove` - Proxy-Host entfernen
  - `nrp list` - Alle Hosts auflisten
  - `nrp status` - Status anzeigen
  - `nrp setup` - System Setup
  - `nrp remote-setup` - Remote Execution Setup

- **Verbesserungen**
  - Bessere Fehlerbehandlung
  - Farbige Terminal-Ausgaben
  - Interaktive und nicht-interaktive Modi
  - Optionale E-Mail für LetsEncrypt
  - Flexible Port-Konfiguration
  - HSTS Header standardmäßig aktiviert

- **Entwicklung**
  - Modern Python Packaging (pyproject.toml)
  - pip-Installation möglich
  - Entwicklungsmodus (`pip install -e .`)
  - Code-Formatierung mit Black
  - Type Hints

### Geändert

- Migration von Bash-Skripten zu Python
- Vereinfachte Befehlsstruktur
- Verbesserte Dokumentation

### Migration von v1.x

Die alten Bash-Skripte befinden sich im `legacy/` Verzeichnis zur Referenz.

| Alt (v1) | Neu (v2) |
|----------|----------|
| `./management.sh` | `nrp add` |
| `./setup.sh` | `sudo nrp setup` |
| `./setup_for_remote_execution.sh` | `sudo nrp remote-setup` |

Siehe [MIGRATION.md](MIGRATION.md) für detaillierte Anleitung.

## [1.x] - Legacy

Bash-basierte Implementation (siehe `legacy/` Verzeichnis)
