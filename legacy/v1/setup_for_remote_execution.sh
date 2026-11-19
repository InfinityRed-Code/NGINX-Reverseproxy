#!/bin/bash
# setup_for_remote_execution.sh
# Dieses Skript bereitet den Reverse Proxy für Remote-Ausführung via SSH vor.

set -e

SCRIPT_PATH="/opt/NGINX-Reverseproxy/management.sh"
USER_NAME="autonginx"
SSH_DIR="/home/$USER_NAME/.ssh"
SUDOERS_FILE="/etc/sudoers.d/${USER_NAME}_nginx"

echo "=== Reverse Proxy Remote Setup ==="

# 1. Benutzer anlegen, falls nicht vorhanden
if id "$USER_NAME" &>/dev/null; then
    echo "Benutzer $USER_NAME existiert bereits."
else
    echo "Lege Benutzer $USER_NAME an..."
    adduser --disabled-password --gecos "" "$USER_NAME"
fi

# 2. SSH-Verzeichnis anlegen
echo "Richte SSH-Verzeichnis ein..."
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$USER_NAME:$USER_NAME" "$SSH_DIR"

# 3. Public Key abfragen
echo "Bitte füge hier den PUBLIC SSH-Key ein (eine Zeile, beginnt meist mit ssh-ed25519 oder ssh-rsa):"
read -r PUB_KEY

echo "$PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$SSH_DIR/authorized_keys"

# 4. sudoers-Eintrag erstellen
echo "Richte sudoers-Berechtigung ein..."
echo "$USER_NAME ALL=(ALL) NOPASSWD: $SCRIPT_PATH" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"

# 5. Prüfen ob Skript existiert
if [[ ! -f "$SCRIPT_PATH" ]]; then
    echo "WARNUNG: $SCRIPT_PATH wurde nicht gefunden!"
else
    echo "Skript $SCRIPT_PATH gefunden."
fi

echo "=== Setup abgeschlossen ==="
echo "Test mit:"
echo "ssh -i /pfad/zum/privaten_schluessel ${USER_NAME}@<Reverseproxy-IP> \"sudo $SCRIPT_PATH <Domain> <IP> http n 80 443\""
