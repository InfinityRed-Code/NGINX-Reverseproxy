#!/bin/bash

# System aktualisieren und benötigte Pakete installieren
apt update
apt install curl net-tools sudo nginx certbot python3 python3-full python3-certbot-nginx openssl -y

# Sicherstellen, dass NGINX aktiviert und gestartet ist
systemctl enable nginx
systemctl start nginx

# Erstellen der Zielverzeichnisse, falls nicht vorhanden
mkdir -p /usr/share/nginx/html/
mkdir -p /etc/nginx/conf.d/
mkdir -p /etc/nginx/ssl/

# Kopieren der Catch-All Ressourcen
cp ./install/404.html /usr/share/nginx/html/
cp ./install/catch-all.conf /etc/nginx/conf.d/

# Selbstsigniertes SSL-Zertifikat erstellen, falls nicht bereits vorhanden
if [ ! -f /etc/nginx/ssl/dummy.crt ] || [ ! -f /etc/nginx/ssl/dummy.key ]; then
  openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/dummy.key \
    -out /etc/nginx/ssl/dummy.crt \
    -subj "/C=DE/ST=RLP/L=Hauenstein/O=SoftENGINE GmbH/OU=IT/CN=SoftENGINE-Reverseproxy"
  echo "Selbstsigniertes Zertifikat wurde erstellt."
else
  echo "Zertifikat existiert bereits – wird nicht überschrieben."
fi

# Entfernen der Standardkonfiguration, damit es keine Konflikte mit dem Catch-All gibt
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default

# Reload der NGINX-Konfiguration nach dem Entfernen der Standardkonfiguration
nginx -s reload

echo "Installation abgeschlossen."