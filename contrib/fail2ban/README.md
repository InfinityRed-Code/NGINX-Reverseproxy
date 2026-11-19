# Fail2Ban auf dem Host (Alternative zu CrowdSec)

In v3 läuft Fail2Ban nicht mehr im Container (rewrite.md 11.5): Bans würden nur den
Container-Namespace betreffen. Die v2-Filter funktionieren weiter, wenn Fail2Ban auf dem
Host die Logs aus `data/logs/nginx/` liest.

```bash
apt install fail2ban
cp filter.d/*.conf /etc/fail2ban/filter.d/
sed "s#NRP_DIR#/opt/nrp#g" jail.d/nrp.conf > /etc/fail2ban/jail.d/nrp.conf
systemctl restart fail2ban
fail2ban-client status nginx-404
```

Hinweise:

- `chain = DOCKER-USER` ist nötig, weil veröffentlichte Container-Ports an `INPUT` vorbeilaufen.
- Echte Client-IP im Access-Log sicherstellen: `"userland-proxy": false` in
  `/etc/docker/daemon.json` (siehe `contrib/crowdsec/README.md`).
- `nrpd` rotiert die nginx-Logs selbst (umbenennen + `nginx -s reopen`); `backend = auto`
  kommt damit zurecht.
