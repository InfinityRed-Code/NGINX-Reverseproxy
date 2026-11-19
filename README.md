# NRP – NGINX Reverse Proxy

NRP ist ein Container, der nginx, die Coraza-WAF (OWASP Core Rule Set), Let's-Encrypt-Zertifikate und
WireGuard-Sites verwaltet. Konfiguriert wird über eine REST-API (mTLS) oder die CLI per `docker exec`.
Der gesamte Zustand liegt in einer SQLite-Datenbank neben der `compose.yaml`.

> Dies ist die containerisierte Neufassung in Go. Die bisherige Python-CLI für Debian-Hosts liegt
> unter [`legacy/v2`](legacy/v2), der Umbauplan in [`rewrite.md`](rewrite.md).

- **Ein Image**: nginx (aus Quellcode, nur benötigte Module), libcoraza, coraza-nginx, CRS und `nrp`. Kein Build auf dem Zielsystem.
- **REST-API** mit Client-Zertifikaten einer internen CA, Rollen `viewer`/`operator`/`admin`, OpenAPI-Vertrag in [`api/openapi.yaml`](api/openapi.yaml), Referenz mit Beispielen in [`docs/api.md`](docs/api.md).
- **Audit-Log** für jede Änderung, mit Hash-Kette (`nrp audit verify`).
- **Datenebene unabhängig von der Steuerungsebene**: Fällt `nrpd` aus, proxyt nginx mit der letzten gültigen Konfiguration weiter.
- **Sichere Änderungen**: Jede Generation wird mit `nginx -t` und einem Coraza-Regelcheck geprüft, bevor sie aktiv wird; Rollback auf die letzten 10 Generationen.

## Schnellstart

```bash
mkdir nrp && cd nrp
curl -fsSLO https://raw.githubusercontent.com/SoftENGINE-IT/NGINX-Reverseproxy/main/deploy/compose.yaml
curl -fsSL  https://raw.githubusercontent.com/SoftENGINE-IT/NGINX-Reverseproxy/main/deploy/.env.example -o .env
$EDITOR .env                                   # Image-Tag, NRP_PUBLIC_ENDPOINT, NRP_API_SANS

mkdir -p data/db data/backups data/logs secrets
head -c 32 /dev/urandom > secrets/master.key && chmod 600 secrets/master.key
docker compose up -d
docker exec -it nrp nrp doctor

alias nrp='docker exec -it nrp nrp'
nrp host add app.example.com -i 192.168.1.10 -p 8080 --wait
```

`secrets/master.key` verschlüsselt alle Geheimnisse in der Datenbank (Zertifikatsschlüssel, WireGuard-Keys,
CA-Schlüssel). **Backup = `data/db` (bzw. `nrp backup`) + `secrets/master.key`.** Ohne den Schlüssel startet der
Dienst nicht, und ein Backup ist ohne ihn wertlos.

Voraussetzungen: Docker mit Compose, Ports 80/443 erreichbar (HTTP-01), für Sites UDP 51820 und das
WireGuard-Kernelmodul (ab Kernel 5.6). Das Datenverzeichnis muss auf einem lokalen Dateisystem liegen (kein NFS/CIFS).

## CLI

Ein Binary, drei Modi:

| Modus | Aufruf | Verbindung |
|---|---|---|
| Lokal | `docker exec -it nrp nrp host list` | Unix-Socket im Container |
| Remote | `nrp --server https://proxy:8443 --cert c.crt --key c.key --ca nrp-ca.crt host list` | mTLS-API |
| Offline (Notfall) | `docker exec -it nrp nrp --offline host list` | direkt auf SQLite, nur wenn der Dienst nicht läuft |

Profile für den Remote-Modus stehen in `~/.config/nrp/config.yaml` (`current:` und `profiles: {name: {server, cert, key, ca}}`).
Alle Befehle kennen `-o table|json|yaml`.

```bash
# Hosts
nrp host add app.example.com -i 192.168.1.10 -p 8080 [-s https] [-e 8444] [-w] [--waf] [--site home] [--wait]
nrp host set app.example.com --waf --no-websockets --client-max-body-size 1g
nrp host list | show FQDN | remove FQDN [--keep-cert] [--revoke]

# Zertifikate und Jobs
nrp cert list | show FQDN | renew FQDN [--wait] | remove FQDN [--revoke]
nrp job list | show ID | wait ID

# WAF: globaler Modus, pro Host per --waf
nrp waf set on | detection-only | off
nrp waf status
nrp waf rules set --file overrides.conf        # eigene Regeln/Ausnahmen, siehe unten

# WireGuard-Sites
nrp site create home --targets 8 [--lan-cidr 192.168.1.0/24]
nrp site install-script home > install-home.sh # auf dem Site-Host ausführen (enthält den PSK)
nrp site set-pubkey home <KEY>
nrp site show home --live
nrp site rotate-psk home | delete home [--keep-config]

# Betrieb
nrp status [-d]            nrp doctor               nrp settings show | set KEY=VALUE
nrp render show | generations | rollback GEN | apply
nrp audit list [--since 24h] | verify | prune --before 90d
nrp backup                 nrp export > nrp.yaml    nrp apply -f nrp.yaml [--prune] [--dry-run]
```

Ein Host ohne Zertifikat hat den Status `pending_certificate` und wird noch nicht ausgeliefert; `--wait` wartet auf die
Ausstellung. Schlägt sie fehl, steht der Grund in `nrp host show` (`status_detail`) und im Job.

Externe Ports ungleich 443 müssen zusätzlich in der `compose.yaml` unter `ports:` veröffentlicht werden.

### Unterschiede zur v2-CLI

`nrp add/remove/list` heißen `nrp host add/remove/list` (`nrp list` bleibt als Alias), die Flags sind gleich.
Ausnahme: `-o` ist jetzt das Ausgabeformat, `--overwrite` hat keine Kurzform mehr. `nrp setup`, `nrp waf enable --rebuild`,
`nrp f2b` und `nrp remote-setup` entfallen (Image statt Installation, mTLS statt SSH). Die vollständige Zuordnung steht in
[`rewrite.md`, Abschnitt 10.3](rewrite.md#103-übersetzungstabelle).

## REST-API

```bash
# Schlüssel bleibt beim Client: CSR erzeugen und signieren lassen
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout alice.key -subj "/CN=alice" -out alice.csr
docker exec -i nrp nrp client issue alice --role admin --csr - < alice.csr > alice.crt
docker exec nrp nrp ca show > nrp-ca.crt

curl --cacert nrp-ca.crt --cert alice.crt --key alice.key https://127.0.0.1:8443/api/v1/hosts
```

- Basis `/api/v1`, Fehler als `application/problem+json`, jede Antwort trägt `X-Request-Id` (derselbe Wert steht im Audit-Log).
- **Optimistic Locking**: `GET` liefert `ETag`, `PATCH`/`PUT`/`DELETE` verlangen `If-Match` (sonst `428`, bei veraltetem Stand `412`). Die CLI setzt den Header selbst.
- `PATCH` ist JSON Merge Patch (`Content-Type: application/merge-patch+json`).
- `POST` akzeptiert `Idempotency-Key`; Wiederholungen liefern 24 h lang die gespeicherte Antwort.
- Zertifikate laufen als Jobs: `201`/`202` mit `Location: /api/v1/jobs/{id}`.
- Die Rolle hängt am SHA-256-Fingerprint des Client-Zertifikats in der Datenbank, nicht an Zertifikatsfeldern.
  `nrp client revoke NAME` wirkt sofort; Client-Zertifikate gelten standardmäßig 90 Tage (`nrp client renew`).
- Die API ist standardmäßig nur auf `127.0.0.1:8443` des Hosts veröffentlicht. Für Zugriff über WireGuard oder ein
  Management-Netz die Portfreigabe in `compose.yaml` und `NRP_API_SANS` anpassen.
- API-Tokens (Bearer) sind optional und aus: `NRP_API_TOKENS_ENABLED=true` und `NRP_API_TOKEN_LISTEN` setzen.

| Darf | viewer | operator | admin |
|---|:-:|:-:|:-:|
| Hosts, Sites, Zertifikate, Status, Jobs lesen | ✓ | ✓ | ✓ |
| Hosts anlegen/ändern/löschen, Zertifikate erneuern | | ✓ | ✓ |
| Sites, WAF-Modus, Settings, Clients/Tokens, Audit, Rollback | | | ✓ |

`nrp audit prune` und `nrp backup` funktionieren nur lokal (Socket bzw. `--offline`).

## Konfiguration

| Variable | Standard | Bedeutung |
|---|---|---|
| `NRP_PUBLIC_ENDPOINT` | – | Öffentlicher Name/IP für WireGuard-Sites, z. B. `proxy.example.com:51820` |
| `NRP_API_LISTEN` | `127.0.0.1:8443` | Bind-Adresse der mTLS-API im Container |
| `NRP_API_SANS` | `localhost,127.0.0.1` | Namen/IPs im Server-Zertifikat der API |
| `NRP_WIREGUARD_ENABLED` | `false` | WireGuard-Hub `wg0` (braucht `NET_ADMIN`) |
| `NRP_WG_OVERLAY_CIDR`, `NRP_WG_PORT` | `10.240.0.0/16`, `51820` | Nur beim Erststart, danach in der DB |
| `NRP_ACME_DIRECTORY` | Let's Encrypt | ACME-Verzeichnis (Staging, interne CA) |
| `NRP_ACME_EMAIL` | – | Kontakt des ACME-Accounts (optional) |
| `NRP_ACME_CA_FILE` | – | Zusätzliches Root-Zertifikat für interne ACME-CAs |
| `NRP_API_TOKENS_ENABLED`, `NRP_API_TOKEN_LISTEN` | `false`, – | Optionaler Token-Listener |
| `NRP_METRICS_LISTEN` | – | Prometheus-Metriken unter `/metrics` |
| `NRP_CROWDSEC_LAPI_URL` | – | Erreichbarkeit von CrowdSec in `nrp status` |
| `NRP_LOG_LEVEL`, `NRP_LOG_MAX_MB`, `NRP_LOG_KEEP` | `info`, `100`, `10` | Dienst-Log, Rotation der nginx-Logs |

Defaults für Hosts (`client_max_body_size`, HSTS) liegen in der Datenbank: `nrp settings set client_max_body_size=200M`.
HSTS `preload` ist standardmäßig aus (praktisch nicht rückgängig zu machen); pro Host mit `--hsts-preload`.

### WAF-Anpassungen

```bash
cat > overrides.conf <<'EOF'
# vor den CRS-Regeln: z. B. Paranoia Level
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=2"
# nrp:after-rules
# nach den CRS-Regeln: Regeln entfernen
SecRuleRemoveById 920350
EOF
docker exec -i nrp nrp waf rules set --file - < overrides.conf
```

Neue Hosts zuerst mit `nrp waf set detection-only` beobachten (`data/logs/coraza/audit.log`). Coraza nutzt Go-Regex (RE2):
Lookaheads wie `(?!…)` sind nicht erlaubt. Eine Regeldatei, die Coraza nicht laden kann, wird abgelehnt und bleibt wirkungslos;
der Fehler steht in `nrp status` und `nrp render generations`.

### Brute-Force-Schutz

Fail2Ban läuft nicht im Container (Bans würden nur den Container-Namespace treffen). Empfohlen ist CrowdSec als
Compose-Profil (`docker compose --profile crowdsec up -d`, Firewall-Bouncer auf dem Host); alternativ Fail2Ban auf dem Host
mit den Filtern unter [`contrib/fail2ban`](contrib/fail2ban). Beide lesen `data/logs/nginx/`. Für echte Client-IPs
`"userland-proxy": false` in `/etc/docker/daemon.json` setzen und im Access-Log prüfen.

## Notfall

```bash
docker exec -it nrp nrp status                      # Generation, letzter Fehler, Jobs
docker exec -it nrp nrp render rollback <GEN>       # letzte funktionierende Konfiguration; hält bis 'render apply'
docker exec -it nrp nrp --offline host list         # wenn nrpd nicht startet
docker exec -it nrp nrp --offline render apply      # offline geänderte Daten anwenden
docker compose run --rm --entrypoint nrp nrp --offline status   # wenn der Container nicht läuft
```

Ein Host, dessen Konfiguration `nginx -t` ablehnt (z. B. nicht auflösbarer Upstream-Hostname), erhält den Status `error`
und wird ausgelassen, bis er geändert wird; alle anderen Hosts werden weiter angewendet.

## Migration von v2

```bash
docker compose run --rm \
  -v /etc/nginx/conf.d:/import/conf.d:ro -v /etc/letsencrypt:/import/letsencrypt:ro \
  -v /var/lib/nrp:/import/nrp:ro -v /etc/wireguard:/import/wireguard:ro \
  --entrypoint nrp nrp --offline import v2 \
    --conf-dir /import/conf.d --letsencrypt /import/letsencrypt \
    --sites /import/nrp/sites.json --wg-conf /import/wireguard/wg0.conf --dry-run
```

Ohne `--dry-run` wird geschrieben. Übernommen werden Hosts (inklusive WAF, WebSockets, Port, HSTS), certbot-Zertifikate,
Sites und der Hub-Schlüssel samt Port; bestehende Sites müssen nichts ändern, solange Endpoint und Port gleich bleiben
(v2 nutzte je nach Stand 51820 oder 51825: den importierten Port in `.env` als `NRP_WG_PORT` veröffentlichen).
Nicht eindeutig lesbare Configs listet der Bericht auf. Danach Host-nginx und `wg-quick@wg0` stoppen, `docker compose up -d`,
`nrp doctor`. Die alten Dateien bleiben unverändert, der Rückweg ist jederzeit möglich.

## Entwicklung

```bash
go test ./...                                   # Unit-, Golden-File-, Store-, API- und Importer-Tests
go test ./internal/render -update               # Golden Files nach Template-Änderungen neu schreiben
go generate ./...                               # API-Code aus api/openapi.yaml (oapi-codegen)
docker run --rm -v "$PWD:/src" -w /src sqlc/sqlc:1.30.0 generate   # Queries (internal/store/queries)

docker build $(sed -e '/^#/d' -e '/^$/d' -e 's/^/--build-arg /' versions.env) -f docker/Dockerfile -t nrp:dev .
bash docker/tests/e2e.sh nrp:dev                # gehärteter Start, WAF-Smoke-Test, nrp doctor
bash docker/tests/e2e-api.sh nrp:dev            # ACME gegen Pebble, Proxy, WAF, mTLS-API, Rollback, Neustart, Offline
bash docker/tests/e2e-wireguard.sh nrp:dev      # Site-Tunnel (braucht NET_ADMIN und das Kernelmodul)
```

Versionen von nginx, Coraza, CRS, Go und den Basis-Images stehen in [`versions.env`](versions.env) und werden von Renovate
gepflegt. Sicherheitspatches vor einem Upstream-Release: [`patches/README.md`](patches/README.md). Details zum Image:
[`docker/README.md`](docker/README.md).

## Lizenz

MIT, siehe [LICENSE](LICENSE).
