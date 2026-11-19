# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

## [Unveröffentlicht] – Neufassung als Container (Go, REST-API, SQLite)

Umsetzung von [`rewrite.md`](rewrite.md). Die Python-CLI (bis 3.2.0) liegt unverändert unter `legacy/v2`.

### Neu

- **Container-Image** auf `debian:trixie-slim`: nginx aus Quellcode (nur benötigte Module), libcoraza und coraza-nginx
  statisch eingebunden, OWASP CRS, s6-overlay, `nrp`. Versionen in `versions.env`, Patch-Verzeichnis `patches/`,
  Build-Smoke-Test mit echter WAF-Anfrage.
- **`nrpd`** (`nrp serve`): REST-API `/api/v1` (OpenAPI in `api/openapi.yaml`) mit mTLS und interner CA, Rollen
  `viewer`/`operator`/`admin`, optionalen API-Tokens, ETag/`If-Match`, `Idempotency-Key`, Fehlern nach RFC 9457.
- **SQLite** als einzige Quelle der Wahrheit (WAL, Migrationen, Geheimnisse mit XChaCha20-Poly1305 verschlüsselt);
  Zertifikate und nginx-Konfiguration werden beim Start nach tmpfs materialisiert.
- **Audit-Log** mit Hash-Kette für jede Änderung, auch für verweigerte und fehlgeschlagene Aktionen
  (`nrp audit list/verify/prune`), zusätzlich als JSON-Zeilen auf stdout.
- **Reconciler**: rendert Generationen, prüft sie mit `nginx -t` und einem Coraza-Regelcheck, schaltet atomar um,
  behält die letzten 10 für `nrp render rollback`. Ein von `nginx -t` abgelehnter Host blockiert andere Änderungen nicht.
- **ACME mit lego** (HTTP-01 über einen globalen Port-80-Server, ARI, Worker-Pool, Retry) statt certbot.
- **WireGuard** über Netlink/wgctrl statt `wg-quick`; Site-Status aus dem Handshake; `nrp site rotate-psk`.
- **CLI** in drei Modi: lokal per Unix-Socket (`docker exec`), remote per mTLS, offline direkt auf der Datenbank.
  Neu u. a. `host set`, `cert`, `job`, `render`, `settings`, `client`, `backup`, `export`/`apply`, `doctor`.
- **Import** einer v2-Installation: `nrp --offline import v2` (Hosts, certbot-Zertifikate, Sites, Hub-Schlüssel).
- CI: Go-Tests mit `-race`, Image-Build, drei E2E-Suiten (gehärteter Start, ACME gegen Pebble inkl. API/WAF/Rollback,
  WireGuard-Tunnel), Trivy, SBOM, cosign; nächtlicher Rebuild; Renovate.

### Geändert (gegenüber der Python-CLI)

- `nrp add/remove/list` → `nrp host add/remove/list` (Flags gleich; `nrp list` bleibt als Alias).
  `-o` ist jetzt das Ausgabeformat, `--overwrite` hat keine Kurzform mehr.
- `nrp waf enable/disable` → `nrp waf set on|detection-only|off`. Standardmodus ist `DetectionOnly`.
- nginx-Templates: `Connection $connection_upgrade` für WebSockets, `proxy_http_version 1.1` immer, `http2 on`,
  IPv6-Listener, `server_tokens off`, eigene TLS-Parameter (Mozilla Intermediate, ohne DHE), ACME auch für Hosts
  mit abweichendem Port. HSTS `preload` ist nicht mehr Standard (importierte Hosts behalten ihren Wert).
- Unbekannte Namen auf Port 443 erhalten kein Zertifikat mehr (`ssl_reject_handshake`) statt einer 404-Seite mit
  Dummy-Zertifikat.
- WireGuard-Standardport ist einheitlich 51820 (`config.py` nutzte 51825, die Doku 51820); der Import übernimmt den
  tatsächlichen Port.

### Entfernt

- `nrp setup`, `nrp waf enable --rebuild/--crs-version`, `nrp remote-setup` (ersetzt durch Image bzw. mTLS-Clients).
- `nrp f2b`: Fail2Ban läuft nicht im Container; CrowdSec als Compose-Profil, Fail2Ban-Filter unter `contrib/fail2ban`.

---

## [3.2.0] - 2026-08-10

### Hinzugefügt

- **Coraza WAF-Integration** (`nrp waf`)
  - Neuer Command-Bereich `nrp waf` auf Basis von [coraza-nginx](https://github.com/corazawaf/coraza-nginx)
  - `nrp waf enable` – baut libcoraza und das coraza-nginx Modul (dynamisch, `--with-compat`, passend zur installierten NGINX-Version), installiert das OWASP Core Rule Set und schreibt das globale Regelwerk
  - `nrp waf enable --detection-only` – Angriffe nur loggen statt blockieren (`SecRuleEngine DetectionOnly`)
  - `nrp waf enable --crs-version <TAG>` – CRS-Version wählbar (Standard: `v4.16.0`)
  - `nrp waf enable --rebuild` – Modul-Neubau, z.B. nach NGINX-Update
  - `nrp waf disable` – setzt `SecRuleEngine Off`, Host-Konfigurationen bleiben gültig
  - `nrp waf status` – Modul-, Regelwerk- und Engine-Status sowie Hosts mit aktiver WAF

- **Globales Regelwerk** (`/etc/nginx/coraza/`)
  - `coraza.conf` – Coraza recommended config: Request-Body-Limits, JSON-Audit-Log (RelevantOnly)
  - `crs-setup.conf` – OWASP CRS Standard-Setup: Anomaly Scoring, Paranoia Level 1, Blocking Mode; bleibt bei erneutem `enable` erhalten (Feintuning/False-Positive-Ausnahmen)
  - `main.conf` – Regelkette, pro Host eingebunden via `coraza_rules_file`

- **WAF pro Proxy-Host**
  - `nrp add --waf / --no-waf` – aktiviert `coraza on;` + globales Regelwerk im Server-Block
  - Interaktive Abfrage bei `nrp add`, sobald die WAF installiert ist
  - Beide Templates (`nginx_standard.conf.j2`, `nginx_custom_port.conf.j2`) erweitert

- **Setup-Erweiterung**
  - `nrp setup --with-waf` – installiert die WAF direkt beim System-Setup

- **Neue Konfigurationskonstanten** in `config.py`
  - `WAF_BUILD_DIR`, `WAF_CONF_DIR`, `WAF_MAIN_CONF`, `WAF_CORAZA_CONF`, `WAF_CRS_DIR`, `WAF_CRS_SETUP_CONF`, `WAF_AUDIT_LOG`, `WAF_MODULE_PATH`, `WAF_MODULE_LOAD_CONF`, `WAF_LIBCORAZA_REPO`, `WAF_CORAZA_NGINX_REPO`, `WAF_CRS_REPO`, `WAF_CRS_VERSION`

---

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
