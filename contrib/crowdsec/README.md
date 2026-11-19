# CrowdSec (empfohlen)

Fail2Ban läuft in v3 nicht mehr im Container (rewrite.md 11.5). CrowdSec liest die nginx-Logs
aus `data/logs/nginx/`, gesperrt wird auf dem **Host**.

```bash
# im Verzeichnis mit compose.yaml; contrib/crowdsec/acquis.yaml daneben ablegen
docker compose --profile crowdsec up -d

# Bouncer-Key erzeugen und den Firewall-Bouncer auf dem Host installieren
docker compose exec crowdsec cscli bouncers add host-firewall
apt install crowdsec-firewall-bouncer-nftables
# /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml:
#   api_url: http://127.0.0.1:8080/
#   api_key: <Key von oben>
systemctl restart crowdsec-firewall-bouncer
```

## Echte Client-IP

Sperren wirken nur, wenn im Access-Log die echte Quell-IP steht. Mit Docker-Bridge-Netzwerk:

- `"userland-proxy": false` in `/etc/docker/daemon.json` setzen und Docker neu starten.
- Danach in `data/logs/nginx/access.log` prüfen, dass nicht die Bridge-Gateway-IP erscheint
  (betrifft vor allem IPv6).
