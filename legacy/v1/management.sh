#!/bin/bash

# Prüfen, ob genau 6 Argumente übergeben wurden
if [ "$#" -eq 6 ]; then
    fqdn="$1"
    internal_ip="$2"
    foreward_scheme="$3"
    enable_websockets="$4"
    internal_port="$5"
    external_port="$6"
    option=2
else
    echo "Was möchten Sie tun?"
    echo "-------------------------------------------------------"
    echo ""
    echo "1: Installation der Umgebung auf einem Debian13 System"
    echo "2: Erstellung eines neuen ProxyHosts"
    echo "3: Setup für Remote-Ausführung via SSH"
    echo ""
    read -p "Wählen Sie eine Option (1 oder 2): " option
fi

if [ "$option" -eq 1 ]; then
    echo "Starte die Installation der Umgebung auf einem Debian13 System..."
    ./setup.sh
    echo "Installation abgeschlossen."
    exit 0
fi

if [ "$option" -eq 3 ]; then
    echo "Starte die Installation der Umgebung auf einem Debian13 System..."
    ./setup_for_remote_execution.sh
    echo "Installation abgeschlossen."
    exit 0
fi

if [ "$option" -eq 2 ]; then
    if [ "$#" -ne 6 ]; then
        read -p "Geben Sie den FQDN an (z.B. server.example.com): " fqdn
        read -p "Geben Sie die IP des internen Servers an: " internal_ip
        read -p "Geben Sie das forward scheme an (http oder https): " foreward_scheme
        read -p "Sollen Websockets aktiviert werden? (y/n): " enable_websockets
        read -p "Geben Sie den Port des internen Servers an (z.B. 8080): " internal_port
        read -p "Geben Sie den externen Port an (z.B. 443): " external_port
    fi

    conf_file="/etc/nginx/conf.d/$fqdn.conf"

    if [ -f "$conf_file" ]; then
        echo "Die Konfigurationsdatei $conf_file existiert bereits."
        read -p "Möchten Sie den Proxy-Host neu anlegen und die Datei überschreiben (o) oder einen neuen Service hinzufügen (h)? (o/h): " choice

        if [ "$choice" == "o" ]; then
            rm "$conf_file"
            echo "Bestehende Datei wird überschrieben."
        else
            echo "Diese Funktion wird derzeit nicht unterstützt."
            exit 1
        fi
    fi

    # Temporäre HTTP-Konfiguration zur Zertifikat-Anforderung
    cat <<EOF > "$conf_file"
server {
    listen 80;
    server_name $fqdn;

    location / {
        return 301 https://\$host:$external_port\$request_uri;
    }
}
EOF

    nginx -s reload
    echo "Temporäre HTTP-Konfiguration aktiv."

    certbot --nginx -d "$fqdn"
    echo "Zertifikat wurde erstellt (wenn erfolgreich)."

    rm "$conf_file"

    if [ "$enable_websockets" == "y" ]; then
        websocket_headers=" # Websocket Header
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$http_connection;
    proxy_http_version 1.1;"
    else
        websocket_headers="# Websocket Header
    # proxy_set_header Upgrade \$http_upgrade;
    # proxy_set_header Connection \$http_connection;
    # proxy_http_version 1.1;"
    fi

    if [ "$external_port" = "443" ]; then
        # Standardkonfiguration mit klassischer 80→443-Umleitung
        cat <<EOF > "$conf_file"
server {
    listen 80;
    server_name $fqdn;

    # Weiterleitung zum verschlüsselten https Port
    return 301 https://\$host$request_uri;
}

server {
    listen 443 ssl;
    server_name $fqdn;

    # Zertifikat
    ssl_certificate /etc/letsencrypt/live/$fqdn/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$fqdn/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Proxy-Host Weiter default HSTS Header 
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Maximale Größe an Files, die übertragen werden darf
    client_max_body_size 100M;

    location / {
        proxy_pass $foreward_scheme://$internal_ip:$internal_port/;

        # Exklusiver HSTS Header, da weitere set_header in der location vorhanden sind
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

        # Default Header    
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Scheme \$scheme;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;
        $websocket_headers
    }
}
EOF

    else
        # Abweichender Port → Fehlerseite 497 für Redirect nutzen
        cat <<EOF > "$conf_file"
server {
    listen $external_port ssl;
    server_name $fqdn;

    # Zertifikat
    ssl_certificate /etc/letsencrypt/live/$fqdn/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$fqdn/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Proxy-Host Weiter default HSTS Header
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Maximale Größe an Files, die übertragen werden darf
    client_max_body_size 100M;

    # Weiterleitung zum verschlüsselten https Port
    # Hier wegen des Abweichen vom den Standard http/https Ports über das Abfangen eines Error 497 Umzusetzen
    # Falls nicht hinzugefügt, kommt beim Aufrufen der http Seite der Fehler: "The plain HTTP request was sent to a HTTPS port"
    error_page 497 https://\$host:$external_port\$request_uri;

    location / {
        proxy_pass $foreward_scheme://$internal_ip:$internal_port/;

        # Exklusiver HSTS Header, da weitere set_header in der location vorhanden sind
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

        # Default Header 
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Scheme \$scheme;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;
        $websocket_headers
    }
}
EOF

    fi

    nginx -s reload
    echo "Finale HTTPS-Konfiguration aktiv."
    exit 0
fi

echo "Ungültige Auswahl. Bitte wählen Sie entweder 1 oder 2 (oder übergeben Sie 6 Parameter direkt)."
exit 1
