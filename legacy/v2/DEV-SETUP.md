# Entwicklungsumgebung Setup

## Für Windows (Entwicklung)

### Automatisches Setup

Führen Sie einfach das Setup-Skript aus:

```cmd
setup-dev.bat
```

### Manuelles Setup

```cmd
# Virtual Environment erstellen
python -m venv venv

# Aktivieren
venv\Scripts\activate

# Dependencies installieren
pip install --upgrade pip
pip install -e .

# Für Entwicklung mit Tests und Tools
pip install -e ".[dev]"
```

### VSCode Setup

Die `.vscode/settings.json` ist bereits konfiguriert. VSCode sollte automatisch:
- Das Virtual Environment erkennen
- Python Linting aktivieren
- Black Formatierung aktivieren
- Pytest Integration aktivieren

**Empfohlene VSCode Extensions:**
- Python (Microsoft)
- Pylance (Microsoft)
- Python Test Explorer

### Import-Fehler beheben

Wenn Sie "Import could not be resolved" Fehler sehen:

1. Stellen Sie sicher, dass das Virtual Environment aktiviert ist:
   ```cmd
   venv\Scripts\activate
   ```

2. Installieren Sie die Dependencies:
   ```cmd
   pip install -e .
   ```

3. VSCode neustarten und Python Interpreter auswählen:
   - `Ctrl+Shift+P` → "Python: Select Interpreter"
   - Wählen Sie `./venv/Scripts/python.exe`

## Für Linux/Debian (Produktion & Entwicklung)

### Automatisches Setup

```bash
chmod +x setup-dev.sh
./setup-dev.sh
```

### Manuelles Setup

```bash
# Virtual Environment erstellen
python3 -m venv venv

# Aktivieren
source venv/bin/activate

# Dependencies installieren
pip install --upgrade pip
pip install -e .

# Für Entwicklung mit Tests und Tools
pip install -e ".[dev]"
```

### System Setup (nur auf Debian/Linux)

```bash
# Aktiviere Virtual Environment
source venv/bin/activate

# Führe System Setup aus
sudo nrp setup
```

## Testen der Installation

### CLI testen

```bash
# Hilfe anzeigen
nrp --help

# Version anzeigen
nrp --version

# Befehle anzeigen
nrp add --help
nrp remove --help
nrp list --help
nrp status --help
```

### Unit Tests ausführen

```bash
# Alle Tests
pytest

# Mit Ausgabe
pytest -v

# Specific test file
pytest tests/test_validation.py

# Mit Coverage
pytest --cov=nrp tests/
```

## Code-Qualität

### Formatierung mit Black

```bash
# Code formatieren
black nrp/

# Check only (ohne änderungen)
black --check nrp/
```

### Linting mit Flake8

```bash
# Code prüfen
flake8 nrp/
```

### Type Checking mit Mypy

```bash
# Type Hints prüfen
mypy nrp/
```

## Troubleshooting

### "Import could not be resolved"

**Problem:** VSCode zeigt Import-Fehler an, obwohl die Packages installiert sind.

**Lösung:**
1. Virtual Environment aktivieren
2. Dependencies installieren: `pip install -e .`
3. VSCode Python Interpreter auswählen: `./venv/Scripts/python.exe` (Windows) oder `./venv/bin/python` (Linux)
4. VSCode neustarten

### "pip: command not found" (Linux)

**Lösung:**
```bash
sudo apt update
sudo apt install python3-pip python3-venv
```

### "python: command not found" (Windows)

**Lösung:**
- Python von [python.org](https://www.python.org/downloads/) installieren
- Bei Installation "Add Python to PATH" aktivieren

## Projekt-Struktur verstehen

```
nrp/
├── __init__.py           # Package Root
├── cli.py                # CLI Entry Point (Click Group)
├── config.py             # Konfigurationskonstanten
├── commands/             # CLI Commands (Subcommands)
│   ├── add.py           # nrp add
│   ├── remove.py        # nrp remove
│   ├── list_cmd.py      # nrp list
│   ├── status.py        # nrp status
│   ├── setup.py         # nrp setup
│   └── remote_setup.py  # nrp remote-setup
├── core/                # Core Funktionalität
│   ├── nginx.py         # NGINX Management Logik
│   ├── certbot.py       # Certbot/LetsEncrypt Logik
│   └── validation.py    # Input Validierung
└── templates/           # Jinja2 Templates
    ├── *.conf.j2        # NGINX Config Templates
    └── 404.html         # Error Page
```

## Neuen Command hinzufügen

1. Erstelle neue Datei in `nrp/commands/`:
   ```python
   # nrp/commands/my_command.py
   import click

   @click.command()
   def my_command():
       """Beschreibung des Commands"""
       click.echo("Hello World")
   ```

2. Registriere in `nrp/cli.py`:
   ```python
   from nrp.commands import my_command
   cli.add_command(my_command.my_command)
   ```

3. Testen:
   ```bash
   nrp my-command
   ```

## Best Practices

- Verwenden Sie Type Hints
- Schreiben Sie Docstrings
- Fügen Sie Tests für neue Features hinzu
- Formatieren Sie Code mit Black vor Commits
- Validieren Sie alle User Inputs
- Behandeln Sie Exceptions sauber
