# Shell-Completion für NRP

Tab-Completion erleichtert die Verwendung von `nrp` erheblich durch automatische Vervollständigung von Befehlen, Optionen und sogar Domain-Namen.

## Schnellinstallation

```bash
nrp completion
```

Das wars! Der Befehl erkennt automatisch Ihre Shell (bash/zsh/fish) und installiert die Completion.

## Manuelle Installation

Falls die automatische Installation nicht funktioniert:

### Bash

```bash
# Completion-Skript generieren
_NRP_COMPLETE=bash_source nrp > ~/.nrp-complete.bash

# Zu .bashrc hinzufügen
echo 'source ~/.nrp-complete.bash' >> ~/.bashrc

# Aktivieren
source ~/.bashrc
```

### Zsh

```bash
# Completion-Skript generieren
_NRP_COMPLETE=zsh_source nrp > ~/.nrp-complete.zsh

# Zu .zshrc hinzufügen
echo 'source ~/.nrp-complete.zsh' >> ~/.zshrc

# Aktivieren
source ~/.zshrc
```

### Fish

```bash
# Completion-Skript generieren
_NRP_COMPLETE=fish_source nrp > ~/.config/fish/completions/nrp.fish

# Fish neustarten
exec fish
```

## Verwendung

Nach der Installation stehen folgende Tab-Completions zur Verfügung:

### Befehle vervollständigen

```bash
nrp <TAB>
# Zeigt: add, remove, list, status, setup, remote-setup, completion
```

### Optionen vervollständigen

```bash
nrp add --<TAB>
# Zeigt: --internal-ip, --internal-port, --external-port, --protocol,
#        --websockets, --email, --overwrite, --full-interactive, --help
```

### Domain-Namen vervollständigen (nrp remove)

```bash
nrp remove <TAB>
# Zeigt: alle konfigurierten Domains (z.B. api.example.com, test.example.com)
```

**Intelligente Filterung:**

```bash
nrp remove api<TAB>
# Zeigt nur: Domains die mit "api" beginnen
```

### Subcommand-Optionen

```bash
nrp add -<TAB>
# Zeigt: -i, -p, -e, -s, -w, -o, -f

nrp remove --<TAB>
# Zeigt: --keep-cert, --help
```

## Vorteile

- ✓ **Schneller**: Keine Tippfehler mehr
- ✓ **Entdeckung**: Sehen Sie alle verfügbaren Optionen
- ✓ **Intelligenz**: Domain-Namen werden aus Ihrer Konfiguration gelesen
- ✓ **Effizienz**: Weniger Tippen, mehr Produktivität

## Fehlerbehebung

### Completion funktioniert nicht

1. **Überprüfen Sie die Installation:**
   ```bash
   cat ~/.nrp-complete.bash   # Bash
   cat ~/.nrp-complete.zsh    # Zsh
   cat ~/.config/fish/completions/nrp.fish  # Fish
   ```

2. **Stellen Sie sicher, dass die Source-Zeile in Ihrer RC-Datei ist:**
   ```bash
   grep nrp ~/.bashrc   # Bash
   grep nrp ~/.zshrc    # Zsh
   ```

3. **Neues Terminal öffnen oder Shell neu laden:**
   ```bash
   source ~/.bashrc   # Bash
   source ~/.zshrc    # Zsh
   exec fish          # Fish
   ```

### `nrp: command not found` beim Generieren

Stellen Sie sicher, dass `nrp` in Ihrem PATH ist:

```bash
which nrp
# Sollte den Pfad zum nrp Binary zeigen
```

Falls nicht, aktivieren Sie das venv oder verwenden Sie den vollen Pfad:

```bash
source /opt/NGINX-Reverseproxy/venv/bin/activate
nrp completion
```

### Domain-Completion zeigt keine Domains

Dies ist normal, wenn noch keine Domains konfiguriert sind. Fügen Sie zuerst einen Host hinzu:

```bash
nrp add test.example.com -i 192.168.1.10 -p 8080
```

Dann sollte `nrp remove <TAB>` die Domain anzeigen.

## Technische Details

- **Framework**: Click's eingebaute Shell-Completion
- **Unterstützte Shells**: Bash, Zsh, Fish
- **Dynamische Completion**: Domain-Namen werden live aus `/etc/nginx/conf.d/` gelesen
- **Caching**: Keine - Domains werden bei jedem Tab neu gelesen (immer aktuell)

## Weitere Informationen

- Click Documentation: https://click.palletsprojects.com/en/8.1.x/shell-completion/
- Bash Completion: https://github.com/scop/bash-completion
- Zsh Completion: https://zsh.sourceforge.io/Doc/Release/Completion-System.html
