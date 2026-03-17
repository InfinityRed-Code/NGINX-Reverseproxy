# NRP - NGINX Reverse Proxy Management Tool

Modernes Python CLI-Tool zur Verwaltung von NGINX Reverse Proxy Konfigurationen auf Debian 13 Systemen.

## Features

- **Einfache CLI-Verwaltung**: Intuitive Befehle wie `nrp add`, `nrp remove`, `nrp list`
- **Automatische SSL-Zertifikate**: Integration mit Let's Encrypt (Certbot)
- **Websocket-Unterstützung**: Optional aktivierbare Websocket-Header
- **Interaktive & Nicht-interaktive Modi**: Flexibel nutzbar in Skripten oder manuell
- **Jinja2 Templates**: Flexible und wartbare Konfigurationsvorlagen
- **Remote Execution**: Sichere Verwaltung über SSH mit eingeschränkten Benutzerrechten
- **Validierung**: Automatische Überprüfung von Eingaben (FQDN, IP, Ports)
- **WireGuard Site-Management**: Hub-and-Spoke-Tunnel zu entfernten Netzwerken – Dienste hinter NAT ohne Port-Forwarding veröffentlichen

## Voraussetzungen

- Debian 13 (oder kompatible Linux-Distribution)
- Python 3.8+
- Root- oder sudo-Zugriff
- Portweiterleitung für Ports 80 und 443 (und weitere verwendete Ports)
- *(Optional für Sites)* UDP-Port 51820 offen für eingehende WireGuard-Verbindungen

## Installation

```bash
# Repository klonen
git clone https://github.com/SoftENGINE-IT/NGINX-Reverseproxy.git
cd NGINX-Reverseproxy

# Python venv erstellen & aktivieren
python3 -m venv venv
source venv/bin/activate

# Installieren
pip install .

# Oder für Entwicklung
pip install -e .

# Symlink hinterlegen für eine Ausführung auch ohne das venv zu aktivieren
sudo ln -s /opt/NGINX-Reverseproxy/venv/bin/nrp /usr/local/bin/nrp
```

## Erste Schritte

### 1. System Setup

```bash
# Installiert NGINX, Certbot und alle Abhängigkeiten
sudo nrp setup

# Mit WireGuard-Unterstützung für Site-Tunnel
sudo nrp setup --with-wireguard
```

Das Setup führt folgende Schritte durch:
- Installation von NGINX, Certbot und Abhängigkeiten
- Aktivierung und Start von NGINX
- Erstellung eines selbstsignierten Dummy-Zertifikats
- Einrichtung einer Catch-All Konfiguration
- Entfernung der Standard-NGINX-Konfiguration
- *(Mit `--with-wireguard`)* Installation von WireGuard, Aktivierung von IP-Forwarding, Initialisierung des Hub-Interface `wg0`

### 1b. Shell-Completion aktivieren (optional, empfohlen)

```bash
# Automatische Installation für Ihre Shell
nrp completion

# Oder manuell für Bash
_NRP_COMPLETE=bash_source nrp > ~/.nrp-complete.bash
echo 'source ~/.nrp-complete.bash' >> ~/.bashrc
source ~/.bashrc
```

**Danach verfügbar:**
- `nrp <TAB>` - Zeigt alle Befehle
- `nrp add --<TAB>` - Zeigt alle Optionen
- `nrp remove <TAB>` - Zeigt konfigurierte Domains

### 2. Konfiguration prüfen und anpassen

In der `nrp/config.py` finden sich alle anpassbaren Parameter/Variablen der verwendeten Programme. 

```python
"""
Configuration settings for NRP
"""
from pathlib import Path

# NGINX Configuration
NGINX_CONF_DIR = Path("/etc/nginx/conf.d")
NGINX_HTML_DIR = Path("/usr/share/nginx/html")
NGINX_SSL_DIR = Path("/etc/nginx/ssl")

# LetsEncrypt Configuration
LETSENCRYPT_DIR = Path("/etc/letsencrypt")
LETSENCRYPT_LIVE_DIR = LETSENCRYPT_DIR / "live"
LETSENCRYPT_OPTIONS_SSL = LETSENCRYPT_DIR / "options-ssl-nginx.conf"
LETSENCRYPT_SSL_DHPARAM = LETSENCRYPT_DIR / "ssl-dhparams.pem"

# Remote Execution Settings
DEFAULT_REMOTE_USER = "autonginx"
DEFAULT_SCRIPT_PATH = "/opt/NGINX-Reverseproxy"

# Template Directory (relative to this file)
TEMPLATE_DIR = Path(__file__).parent / "templates"

# Default Values
DEFAULT_CLIENT_MAX_BODY_SIZE = "100M"
DEFAULT_HSTS_MAX_AGE = 31536000  # 1 year in seconds

```

Alle hier aufgelisteten Verzeichnisse können theoretisch angepasst werden, jedoch muss danach sichergestellt werden, dass der ausführende Benutzer die entsprechenden Berechtigungen dafür hat, genau wie certbot und der Webserver NGINX.

Was bedenkenlos angepasst werden kann sind `DEFAULT_CLIENT_MAX_BODY_SIZE` und `DEFAULT_HSTS_MAX_AGE`.

`DEFAULT_CLIENT_MAX_BODY_SIZE` bestimmt wie groß dass Dateien maximal sein dürfen, falls buffering deaktiviert wurde. Dabei sind jedoch nach Best Practices der niedrigste mögliche Wert empfohlen für die daheinter leigende Anwendung. Muss ich also z.B. für eine Website maximal Dateien hochladen, die 150MB groß sind, so sollte ich den Wert auf 150M setzen. Dieser Wert kann daher auch verwendet werden, um das hochladen von zu großen Files durch Ungeschulte zu unterbinden.

`DEFAULT_HSTS_MAX_AGE` bestimmt wie lange der benutzer Web-Browser sich merkt, dass für diese Website https (also eine TLS Verschlüsselung aller gesendeter Daten) erzwungen ist. Dies stellt sicher, dass selbst fest hinterlegte http Links mit https aufgerufen werden. Außerdem verringert es die Kommunikation zwischen Client und Server, da nicht jedes Mal beim Server angefragt werden muss, um die Verbindung upzugraden. Außerdem stellt es Verschlüsslung sicher, selbst wenn der Webserver keinen automatischen rewrite zu 443 haben sollte. Für HSTS empfehlen sich nach Industriestandard Werte ab einem halben Jahr.

### 3. Proxy-Host hinzufügen

#### Interaktiv - Basis-Modus (empfohlen für Einsteiger)

```bash
nrp add
```

Das Tool fragt nach den wichtigsten Parametern:
- FQDN (z.B. `api.example.com`)
- Interne IP-Adresse (z.B. `192.168.1.10`)
- Interner Port (z.B. `8080`)
- Websockets aktivieren (ja/nein)

**Standard-Werte:**
- Externer Port: `443`
- Forward Scheme: `http`
- E-Mail: keine

#### Interaktiv - Vollständiger Modus

```bash
nrp add --full-interactive
# oder kurz:
nrp add -f
```

Das Tool fragt nach **allen** verfügbaren Optionen:
- FQDN, Interne IP, Interner Port, Websockets (wie oben)
- **Plus:** Externer Port, Forward Scheme (http/https), E-Mail für LetsEncrypt

Ideal für benutzerdefinierte Konfigurationen.
Weitere Infos zu den Optionen finden sich im Bereich [CLI-Referenz](#cli-referenz)

#### Mit Parametern (für Automatisierung)

```bash
nrp add example.com \
  --internal-ip 192.168.1.10 \
  --internal-port 8080 \
  --external-port 443 \
  --protocol http \
  --websockets
```

Kurzform:

```bash
nrp add example.com -i 192.168.1.10 -p 8080
```

#### Via WireGuard-Tunnel (Site als Upstream)

Wenn die Anwendung hinter einem NAT liegt und über eine Site erreichbar ist:

```bash
nrp add app.example.com \
  --site home \
  --internal-ip 10.240.0.5 \
  --internal-port 3000 \
  --external-port 443 \
  --protocol http
```

Das Tool prüft automatisch, dass `--internal-ip` im Subnetz der angegebenen Site liegt.

### 4. Site-Management (WireGuard-Tunnel)

Sites ermöglichen es, Dienste aus entfernten Netzwerken (z.B. Heimnetz hinter NAT) über einen verschlüsselten WireGuard-Tunnel durch den VPS zu veröffentlichen.

**Topologie:**

```
Heimnetz / Büro                   VPS (Hub)
┌─────────────────┐               ┌──────────────────────┐
│  Dienst :3000   │               │  NGINX               │
│  10.240.0.5     │◄─ WireGuard ─►│  wg0 (10.240.0.1)    │
│  Site-Host      │   Tunnel      │  → proxy_pass        │
│  10.240.0.2     │               │    10.240.0.5:3000    │
└─────────────────┘               └──────────────────────┘
                                         ▲
                                  Öffentliches Internet
                                  (Port 443 HTTPS)
```

**Typischer Workflow:**

```bash
# 1. Site anlegen (Subnetz wird automatisch vergeben)
nrp site create home --targets 8

# 2. Install-Script generieren
nrp site install-script home > install-home.sh

# 3. Script auf den Site-Host übertragen und ausführen
scp install-home.sh user@site-host:/tmp/
ssh user@site-host 'bash /tmp/install-home.sh'

# 4. Public Key registrieren (wird vom Script ausgegeben)
nrp site set-pubkey home <PUBLIC_KEY_AUS_SCRIPT_OUTPUT>

# 5. Anwendung freigeben
nrp add app.example.com --site home -i 10.240.0.5 -p 3000

# 6. Status prüfen
nrp site list
nrp site show home --live
```

### 5. Weitere Befehle

```bash
# Alle Proxy-Hosts auflisten
nrp list

# Proxy-Host entfernen
nrp remove example.com

# Status anzeigen
nrp status
nrp status --detailed

# Hilfe anzeigen
nrp --help
nrp add --help
nrp site --help
```

## CLI-Referenz

### `nrp setup`

Installiert die Umgebung auf einem Debian 13 System.

```bash
sudo nrp setup [--skip-packages] [--with-wireguard]
```

**Optionen:**
- `--skip-packages`: Überspringt die Paketinstallation
- `--with-wireguard`: Installiert WireGuard, aktiviert IP-Forwarding und initialisiert `wg0`

### `nrp add`

Erstellt einen neuen Proxy-Host.

```bash
nrp add [FQDN] [OPTIONS]
```

**Optionen:**
- `-i, --internal-ip TEXT`: Interne IP-Adresse
- `-p, --internal-port INTEGER`: Interner Port
- `-e, --external-port INTEGER`: Externer Port (Standard: 443)
- `-s, --protocol [http|https]`: Forward Scheme (Standard: http)
- `-w, --websockets / -nw, --no-websockets`: Websockets aktivieren
- `--email TEXT`: E-Mail für LetsEncrypt Benachrichtigungen
- `-o, --overwrite`: Bestehende Konfiguration überschreiben
- `-f, --full-interactive`: Alle Optionen interaktiv abfragen (statt nur Basis-Parameter)
- `--site TEXT`: Name einer vorhandenen WireGuard-Site; `--internal-ip` muss im Subnetz der Site liegen

**Beispiele:**

```bash
# Interaktiv (Basis) - fragt nur FQDN, IP, Port, Websockets
nrp add

# Interaktiv (Vollständig) - fragt ALLE Optionen
nrp add --full-interactive
nrp add -f

# Minimale Angaben per Parameter
nrp add api.example.com -i 192.168.1.10 -p 8080

# Mit Websockets
nrp add ws.example.com -i 192.168.1.20 -p 3000 -w

# Eigener Port mit HTTPS Backend
nrp add secure.example.com -i 192.168.1.30 -p 8443 -e 9443 -s https

# Mit E-Mail für Zertifikate
nrp add example.com -i 192.168.1.10 -p 8080 --email admin@example.com

# Via WireGuard-Tunnel (Site muss vorher angelegt sein)
nrp add app.example.com --site home -i 10.240.0.5 -p 3000
```

### `nrp site`

Verwaltet WireGuard-Tunnel-Sites (Hub-and-Spoke).

#### `nrp site create`

```bash
nrp site create NAME [OPTIONS]
```

**Optionen:**
- `--targets INTEGER`: Anzahl interner Dienste – bestimmt Subnetz-Größe (1–2 → /30, 3–6 → /29, 7–14 → /28, 15–30 → /27 …)
- `--subnet-prefix INTEGER`: Expliziter Präfix (z.B. `28` für `/28`), überschreibt `--targets`
- `--email TEXT`: E-Mail für Metadaten
- `--os [debian|ubuntu|alpine]`: OS-Hinweis für das Install-Script

**Beispiele:**

```bash
nrp site create home --targets 8
nrp site create office --subnet-prefix 27
nrp site create lab --targets 4 --email admin@example.com --os debian
```

#### `nrp site list`

```bash
nrp site list
```

Tabellarische Übersicht aller Sites mit Name, Subnetz, Connector-IP und Status.

#### `nrp site show`

```bash
nrp site show NAME [--live]
```

**Optionen:**
- `--live`: Pingt die Connector-IP und zeigt den aktuellen Verbindungsstatus

#### `nrp site delete`

```bash
nrp site delete NAME [--keep-config] [--yes]
```

**Optionen:**
- `--keep-config`: Entfernt den WireGuard-Peer aus `wg0.conf`, behält aber die Metadaten in der DB
- `--yes / -y`: Ohne Bestätigungsdialog löschen

#### `nrp site install-script`

```bash
nrp site install-script NAME [--os debian|ubuntu|alpine] > install-NAME.sh
```

Generiert ein Bash-Script, das auf dem Site-Host WireGuard installiert, ein Key-Paar erzeugt, die Tunnel-Konfiguration schreibt und den Public Key ausgibt.

#### `nrp site set-pubkey`

```bash
nrp site set-pubkey NAME PUBLIC_KEY
```

Speichert den Public Key des Site-Hosts und aktualisiert `wg0.conf`. Wird nach dem Ausführen des Install-Scripts aufgerufen.

---

### `nrp remove`

Entfernt einen Proxy-Host.

```bash
nrp remove FQDN [--keep-cert]
```

**Optionen:**
- `--keep-cert`: Zertifikat behalten (nicht löschen)

**Beispiel:**

```bash
nrp remove example.com
nrp remove example.com --keep-cert
```

### `nrp list`

Zeigt alle konfigurierten Proxy-Hosts.

```bash
nrp list
```

### `nrp status`

Zeigt den Status von NGINX und Zertifikaten.

```bash
nrp status [-d, --detailed]
```

**Optionen:**
- `-d, --detailed`: Zeigt detaillierte Informationen

### `nrp remote-setup`

Konfiguriert Remote-Ausführung via SSH.

```bash
sudo nrp remote-setup [OPTIONS]
```

**Optionen:**
- `-u, --user TEXT`: Benutzername (Standard: autonginx)
- `-s, --script-path TEXT`: Installationspfad (Standard: /opt/NGINX-Reverseproxy)
- `-k, --public-key TEXT`: Pfad zum öffentlichen SSH-Schlüssel

**Beispiel:**

```bash
sudo nrp remote-setup --user myuser --public-key ~/.ssh/id_ed25519.pub
```

### `nrp completion`

Installiert Shell-Completion (Tab-Vervollständigung).

```bash
nrp completion [--shell SHELL]
```

**Optionen:**
- `--shell [bash|zsh|fish]`: Shell-Typ (wird automatisch erkannt)

**Beispiel:**

```bash
# Automatische Erkennung
nrp completion

# Spezifische Shell
nrp completion --shell bash
```

**Was wird aktiviert:**
- Vervollständigung von Befehlen: `nrp <TAB>`
- Vervollständigung von Optionen: `nrp add - <TAB>`
- Vervollständigung von Optionen: `nrp add -- <TAB>`
- Vervollständigung von Domains: `nrp remove <TAB>` zeigt alle konfigurierten Hosts

## Secure Remote Execution

Die sichere Remote-Ausführung ermöglicht es, das Tool von einem entfernten System aus zu verwenden:

### Setup auf dem Server:

```bash
sudo nrp remote-setup
```

Dieser Befehl:
1. Erstellt einen eingeschränkten Benutzer (Standard: `autonginx`)
2. Richtet SSH-Zugriff mit Key-Authentifizierung ein
3. Gewährt sudo-Rechte nur für den `nrp` Befehl
4. Keine Passwortabfrage nötig (NOPASSWD)

### Verwendung vom Remote-System:

```bash
# Hosts auflisten
ssh -i ~/.ssh/id_ed25519 autonginx@reverseproxy.example.com "sudo nrp list"

# Neuen Host hinzufügen
ssh -i ~/.ssh/id_ed25519 autonginx@reverseproxy.example.com \
  "sudo nrp add api.example.com -i 192.168.1.10 -p 8080"

# Host entfernen
ssh -i ~/.ssh/id_ed25519 autonginx@reverseproxy.example.com \
  "sudo nrp remove api.example.com"
```

## Konfiguration

### Verzeichnisse

- NGINX Konfigurationen: `/etc/nginx/conf.d/`
- SSL Zertifikate: `/etc/letsencrypt/live/`
- HTML Ressourcen: `/usr/share/nginx/html/`
- Dummy SSL Zertifikat: `/etc/nginx/ssl/`
- WireGuard Hub-Konfiguration: `/etc/wireguard/wg0.conf`
- Site-Datenbank: `/var/lib/nrp/sites.json`

### WireGuard-Konfiguration

Die folgenden Werte können in `nrp/config.py` angepasst werden:

| Variable | Standard | Beschreibung |
|---|---|---|
| `WG_OVERLAY_CIDR` | `10.240.0.0/16` | Overlay-Netzwerk für alle Tunnel-Subnetze |
| `WG_INTERFACE_NAME` | `wg0` | Name des Hub-WireGuard-Interface |
| `WG_CONFIG_PATH` | `/etc/wireguard/wg0.conf` | Pfad zur Hub-Konfiguration |
| `WG_PORT` | `51820` | UDP-Port für WireGuard (muss in Firewall freigegeben sein) |
| `NRP_DATA_DIR` | `/var/lib/nrp` | Verzeichnis für die Site-Datenbank |

### Beispiel einer generierten Konfiguration

**Mit Standard-Port 443:**

```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    client_max_body_size 100M;

    location / {
        proxy_pass http://192.168.1.10:8080/;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Scheme $scheme;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;

        # Websocket Header (wenn aktiviert)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_http_version 1.1;
    }
}
```

### Verhalten bei non Standard Ports

Bei abweichenden Standardports kommt es normalerweise zu einem Problem, da automatische http rewrites zu https im Standard nur möglich sind, da der Webserver die Website technisch einmal unverschlüsselt auf Port 80 und einmal verschlüsselt auf Port 443 bereit stellt. Diese Ports sind der Standard und müssen im Browser nicht explizit angegeben werden. Führt der Browser nun nicht selbst, wie viele Chromium basierte es mittlwereile tun, einen https rewrite durch, so würde bei einem externen Port 8080 ein Fehler kommen, dass versucht wird eine https Webite per http zu besuchen.

Hierfür wird die `error_page` Direktive benutzt. Der Fehlercode `497` fängt dabei genau dieses Verhalten ab und erlaubt eine entprechende, abweichende Reaktion für den Webserver zu hinterlegen. In diesem Fall ein Upgrade der Session zu https.

## Fehlerbehebung

### NGINX Konfiguration testen

```bash
nginx -t
```

### NGINX Logs anzeigen

```bash
# Error Log
tail -f /var/log/nginx/error.log

# Access Log
tail -f /var/log/nginx/access.log
```

### NGINX Status prüfen

```bash
systemctl status nginx

# Oder mit nrp
nrp status
```

### Zertifikate manuell erneuern

```bash
certbot renew
```

### WireGuard-Tunnel debuggen

```bash
# Hub-Status anzeigen (alle verbundenen Peers)
wg show wg0

# Tunnel-Konfiguration prüfen
cat /etc/wireguard/wg0.conf

# Site-Konnektivität testen (Ping zur Connector-IP)
nrp site show home --live
ping 10.240.0.2

# WireGuard-Logs
journalctl -u wg-quick@wg0 -f

# IP-Forwarding prüfen
sysctl net.ipv4.ip_forward
```

## Migration von v1 (Bash-Skripte)

Die alten Bash-Skripte befinden sich im `legacy/` Verzeichnis zur Referenz.

Siehe [MIGRATION.md](MIGRATION.md) für detaillierte Migrationsanleitung.

**Befehlsvergleich:**

| Alt | Neu |
|-----|-----|
| `./management.sh` | `nrp add` |
| `./setup.sh` | `sudo nrp setup` |
| `./setup_for_remote_execution.sh` | `sudo nrp remote-setup` |

## Entwicklung

### Entwicklungsumgebung einrichten

```bash
# Repository klonen
git clone https://github.com/SoftENGINE-IT/NGINX-Reverseproxy.git
cd NGINX-Reverseproxy

# Virtual Environment erstellen
python -m venv venv
source venv/bin/activate  # Oder auf Windows: venv\Scripts\activate

# Im Entwicklungsmodus installieren
pip install -e ".[dev]"
```

### Tests ausführen

```bash
pytest
```

### Code formatieren

```bash
black nrp/
```

## Projektstruktur

```
NRPv2/
├── nrp/                          # Python Package
│   ├── __init__.py
│   ├── cli.py                    # CLI Entry Point
│   ├── config.py                 # Konfiguration (inkl. WireGuard-Konstanten)
│   ├── commands/                 # CLI Commands
│   │   ├── add.py               # Host hinzufügen (inkl. --site)
│   │   ├── remove.py            # Host entfernen (mit Domain-Completion)
│   │   ├── list_cmd.py          # Hosts auflisten
│   │   ├── status.py            # Status anzeigen
│   │   ├── setup.py             # System Setup (inkl. --with-wireguard)
│   │   ├── remote_setup.py      # Remote Execution Setup
│   │   ├── site.py              # Site-Management (WireGuard)
│   │   └── completion.py        # Shell-Completion Installation
│   ├── core/                     # Core Funktionalität
│   │   ├── nginx.py
│   │   ├── certbot.py
│   │   ├── validation.py
│   │   └── wireguard.py         # WireGuard Site-DB & Hub-Konfiguration
│   └── templates/                # Jinja2 Templates
│       ├── nginx_standard.conf.j2
│       ├── nginx_custom_port.conf.j2
│       ├── catch-all.conf.j2
│       └── 404.html
├── legacy/                       # Alte Bash Scripts
├── tests/                        # Unit Tests
├── pyproject.toml                # Python Packaging
├── requirements.txt
├── README.md
├── MIGRATION.md
├── COMPLETION.md                 # Shell-Completion Anleitung
└── LICENSE
```

## Lizenz

MIT License - siehe [LICENSE](LICENSE) Datei.

## Support

Bei Problemen oder Fragen:
- GitHub Issues: https://github.com/SoftENGINE-IT/NGINX-Reverseproxy/issues
- E-Mail: info@softengine-it.de

## Autor

**SoftENGINE IT**
- Website: https://www.softengine-it.de
- GitHub: https://github.com/SoftENGINE-IT
