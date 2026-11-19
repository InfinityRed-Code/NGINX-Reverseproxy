# Migration zu NRP v2.0

## Schritt 1: Alte Bash-Skripte verschieben

Führen Sie folgende Befehle aus (auf Linux/Git Bash):

```bash
# Erstelle legacy Verzeichnis (falls nicht vorhanden)
mkdir -p legacy

# Verschiebe alte Bash-Skripte
mv management.sh legacy/
mv setup.sh legacy/
mv setup_for_remote_execution.sh legacy/

# Behalte install/ Verzeichnis für Referenz oder verschiebe es
# mv install/ legacy/install/
```

Oder auf Windows (PowerShell):

```powershell
# Erstelle legacy Verzeichnis
New-Item -ItemType Directory -Force -Path legacy

# Verschiebe Dateien
Move-Item management.sh legacy/
Move-Item setup.sh legacy/
Move-Item setup_for_remote_execution.sh legacy/
```

## Schritt 2: Installation

### Auf dem Zielsystem (Debian/Linux):

```bash
# 1. Repository klonen oder pullen
git clone https://github.com/SoftENGINE-IT/NGINX-Reverseproxy.git
cd NGINX-Reverseproxy

# 2. Python Package installieren
pip install .

# Oder für Entwicklung:
pip install -e .

# 3. System Setup durchführen
sudo nrp setup

# 4. (Optional) Remote Setup
sudo nrp remote-setup
```

## Schritt 3: Verwendung

### Neue CLI-Befehle:

```bash
# Proxy-Host hinzufügen (interaktiv)
nrp add

# Proxy-Host hinzufügen (mit Parametern)
nrp add example.com -i 192.168.1.10 -p 8080

# Mit allen Optionen
nrp add test.example.com \
  --internal-ip 192.168.1.20 \
  --internal-port 3000 \
  --external-port 8443 \
  --protocol https \
  --websockets

# Proxy-Host entfernen
nrp remove example.com

# Alle Hosts auflisten
nrp list

# Status anzeigen
nrp status
nrp status --detailed

# System Setup
sudo nrp setup

# Remote Setup
sudo nrp remote-setup
```

## Befehlsvergleich

| Alt (Bash) | Neu (Python CLI) |
|------------|------------------|
| `./management.sh` | `nrp add` |
| `./management.sh domain 192.168.1.10 http n 8080 443` | `nrp add domain -i 192.168.1.10 -p 8080` |
| `./setup.sh` | `sudo nrp setup` |
| `./setup_for_remote_execution.sh` | `sudo nrp remote-setup` |
| - | `nrp list` |
| - | `nrp remove domain` |
| - | `nrp status` |

## Vorteile

- ✓ Bessere Fehlerbehandlung
- ✓ Interaktive und Nicht-interaktive Modi
- ✓ Klare Subcommands (`nrp add`, `nrp remove`, etc.)
- ✓ Validierung von Eingaben
- ✓ Farbige Ausgaben
- ✓ Einfachere Installation via pip
- ✓ Jinja2 Templates für flexiblere Konfigurationen
- ✓ Unit-Tests möglich
