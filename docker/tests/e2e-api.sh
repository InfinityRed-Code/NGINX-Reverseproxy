#!/usr/bin/env bash
# Funktionaler E2E-Test gegen ein fertig gebautes NRP-Image:
#
#   docker/tests/e2e-api.sh nrp:dev
#
# Baut ein isoliertes Docker-Netz mit ACME-Test-CA (Pebble + challtestsrv) und einem
# Backend auf und prueft den gesamten Weg unter den Haertungsoptionen aus compose.yaml:
#   1. Host anlegen -> Zertifikat per ACME HTTP-01 -> nginx proxyt per TLS zum Backend
#   2. WAF: DetectionOnly laesst durch, On blockiert (403); defekte Regeln werden nicht angewendet
#   3. REST-API: mTLS, Rollen, ETag/If-Match, Audit-Kette
#   4. Rollback, Quarantaene fuer defekte Hosts, Offline-Sperre, Backup
#   5. Container-Neustart: tmpfs leer, Zustand kommt vollstaendig aus der DB
#   6. Erneuerung (cert renew) laedt das neue Zertifikat in nginx
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE="${1:?usage: e2e-api.sh <image>}"
P="nrp-api-e2e-$$"
NET="$P-net"
SUBNET="${E2E_SUBNET:-10.77.31.0/24}"
NRP_IP="${SUBNET%.*}.10"
NRP="$P-nrp"
PEBBLE_IMG="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
CHALL_IMG="${CHALLTESTSRV_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:latest}"
BACKEND_IMG="${BACKEND_IMAGE:-traefik/whoami:latest}"
CURL_IMG="${CURL_IMAGE:-curlimages/curl:latest}"
WORK="$(mktemp -d)"
# Git Bash unter Windows: docker cp braucht einen Windows-Pfad.
if command -v cygpath >/dev/null 2>&1; then WORK="$(cygpath -m "$WORK")"; fi
STEP=0

step() { STEP=$((STEP + 1)); echo "[$STEP] $*"; }
fail() {
  echo "E2E FEHLER (Schritt $STEP): $*" >&2
  echo "--- nrp status ---" >&2; docker exec "$NRP" nrp status >&2 2>&1 || true
  echo "--- docker logs (nrp) ---" >&2; docker logs "$NRP" 2>&1 | grep -v '"msg":"audit"' | tail -30 >&2 || true
  exit 1
}
cleanup() {
  docker rm -f "$NRP" "$P-pebble" "$P-chall" "$P-backend" "$P-curl" >/dev/null 2>&1 || true
  docker volume rm -f "$P-data" "$P-logs" "$P-secret" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

nrp() { docker exec "$NRP" nrp "$@"; }
nrpi() { docker exec -i "$NRP" nrp "$@"; }
# curl aus einem Hilfscontainer im selben Netz; /w ist das Arbeitsverzeichnis mit Zertifikaten.
kurl() { docker exec "$P-curl" curl -sS --max-time 15 "$@"; }
code() { kurl -o /dev/null -w '%{http_code}' "$@" || true; }
https() { local host="$1"; shift; kurl -k --resolve "$host:443:$NRP_IP" "$@"; }
put() { docker cp "$1" "$P-curl:/w/$(basename "$1")" >/dev/null; }
expect() { local what="$1" want="$2" got="$3"; [ "$got" = "$want" ] || fail "$what: erhalten '$got', erwartet '$want'"; }
contains() { grep -q -- "$2" <<<"$1" || fail "$3 (gesucht: $2)
$1"; }

# ── Umgebung ────────────────────────────────────────────────────────────────
step "Netz, Backend, ACME-Test-CA (Pebble)"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name "$P-backend" --network "$NET" --network-alias backend "$BACKEND_IMG" >/dev/null
docker run -d --name "$P-chall" --network "$NET" --network-alias challtestsrv "$CHALL_IMG" \
  -defaultIPv4 "$NRP_IP" -defaultIPv6 "" -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
# Pebble validiert HTTP-01 auf Port 80 (Standardkonfiguration nutzt 5002).
docker create --name "$P-pebble" --network "$NET" --network-alias pebble \
  -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  "$PEBBLE_IMG" -config /test/config/e2e.json -dnsserver challtestsrv:8053 >/dev/null
docker cp "$P-pebble:/test/config/pebble-config.json" - | tar -xO > "$WORK/pebble.json"
sed -e 's/"httpPort": *[0-9]*/"httpPort": 80/' -e 's/"tlsPort": *[0-9]*/"tlsPort": 443/' "$WORK/pebble.json" > "$WORK/e2e.json"
docker cp "$WORK/e2e.json" "$P-pebble:/test/config/e2e.json" >/dev/null
docker cp "$P-pebble:/test/certs/pebble.minica.pem" - | tar -xO > "$WORK/pebble-ca.pem"
docker start "$P-pebble" >/dev/null
docker run -d --name "$P-curl" --network "$NET" --user 0 --workdir /w --entrypoint sleep "$CURL_IMG" 3600 >/dev/null
docker exec "$P-curl" mkdir -p /w

step "NRP-Container (read-only, cap-drop ALL, tmpfs)"
docker run --rm --entrypoint sh -v "$P-data:/d" -v "$P-logs:/l" -v "$P-secret:/s" "$IMAGE" -c '
  mkdir -p /d/db /d/backups && head -c 32 /dev/urandom > /s/master.key && chmod 600 /s/master.key
  chown -R 1000:1000 /d /l /s && chmod 755 /d /d/db /d/backups /l /s'
docker run --rm -i --entrypoint sh -v "$P-secret:/s" "$IMAGE" -c 'cat > /s/pebble-ca.pem' < "$WORK/pebble-ca.pem"
start_nrp() {
  docker run -d --name "$NRP" --network "$NET" --ip "$NRP_IP" \
    --read-only --tmpfs /run:exec,mode=0755 --tmpfs /var/cache/nginx --tmpfs /tmp \
    --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges:true \
    --mount "type=volume,src=$P-data,dst=/var/lib/nrp/db,volume-subpath=db" \
    --mount "type=volume,src=$P-data,dst=/var/lib/nrp/backups,volume-subpath=backups" \
    -v "$P-logs:/var/log/nrp" \
    --mount "type=volume,src=$P-secret,dst=/run/secrets/nrp_master_key,volume-subpath=master.key,readonly" \
    --mount "type=volume,src=$P-secret,dst=/etc/nrp-e2e,readonly" \
    -e NRP_API_LISTEN=0.0.0.0:8443 -e "NRP_API_SANS=$NRP_IP,nrp.e2e.test" \
    -e NRP_WIREGUARD_ENABLED=false \
    -e NRP_ACME_DIRECTORY=https://pebble:14000/dir -e NRP_ACME_CA_FILE=/etc/nrp-e2e/pebble-ca.pem \
    -e NRP_METRICS_LISTEN=0.0.0.0:9100 \
    "$IMAGE" >/dev/null
  for i in $(seq 1 40); do
    if nrp health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "nrp health wurde nicht gruen"
}
start_nrp
nrp doctor >/dev/null || fail "nrp doctor"
expect "unbekannter Name auf Port 80" 404 "$(code "http://$NRP_IP/")"

# ── 1. Host + ACME + Proxy ──────────────────────────────────────────────────
step "Host anlegen, Zertifikat per ACME HTTP-01, Proxy zum Backend"
nrp host add app.e2e.test -i backend -p 80 --waf --wait --wait-timeout 2m >/dev/null || fail "host add --wait"
out="$(nrp host show app.e2e.test)"
contains "$out" "active" "Host ist nach --wait nicht active"
out="$(nrp cert list)"
contains "$out" "app.e2e.test" "Zertifikat fehlt in cert list"
contains "$out" "acme" "Zertifikat stammt nicht aus ACME"
body="$(https app.e2e.test https://app.e2e.test/hello)"
contains "$body" "GET /hello" "Backend-Antwort ueber TLS-Proxy"
contains "$body" "X-Forwarded-Proto: https" "X-Forwarded-Proto fehlt"
contains "$body" "X-Real-Ip: ${SUBNET%.*}." "X-Real-IP fehlt"
hdrs="$(https app.e2e.test -D - -o /dev/null https://app.e2e.test/)"
contains "$hdrs" "strict-transport-security: max-age=31536000; includeSubDomains" "HSTS-Header"
grep -qi "preload" <<<"$hdrs" && fail "HSTS preload darf nicht Standard sein"
grep -qi "^server: nginx/" <<<"$hdrs" && fail "server_tokens ist nicht off"
contains "$(https app.e2e.test --http2 -o /dev/null -w '%{http_version}' https://app.e2e.test/)" "2" "HTTP/2 nicht aktiv"
expect "HTTP -> HTTPS" 301 "$(code --resolve "app.e2e.test:80:$NRP_IP" http://app.e2e.test/x)"
# Unbekannter Name auf 443: kein Zertifikat, Handshake wird abgelehnt.
expect "unbekannter SNI" 000 "$(https nope.e2e.test -o /dev/null -w '%{http_code}' https://nope.e2e.test/ 2>/dev/null || true)"
issuer="$(docker exec "$P-curl" sh -c "curl -skv --resolve app.e2e.test:443:$NRP_IP https://app.e2e.test/ -o /dev/null 2>&1 | grep -i 'issuer:'")"
contains "$issuer" "Pebble" "Zertifikat stammt nicht von der Test-CA"

# ── 2. WAF ──────────────────────────────────────────────────────────────────
step "WAF: DetectionOnly protokolliert, On blockiert"
XSS='https://app.e2e.test/?q=%3Cscript%3Ealert(1)%3C/script%3E'
contains "$(nrp waf status)" "DetectionOnly" "Standardmodus ist nicht DetectionOnly"
expect "XSS bei DetectionOnly" 200 "$(https app.e2e.test -o /dev/null -w '%{http_code}' "$XSS")"
nrp waf set on >/dev/null
for i in $(seq 1 20); do
  c="$(https app.e2e.test -o /dev/null -w '%{http_code}' "$XSS")"; [ "$c" = 403 ] && break; sleep 0.5
done
expect "XSS bei On" 403 "$c"
expect "harmlose Anfrage bei On" 200 "$(https app.e2e.test -o /dev/null -w '%{http_code}' https://app.e2e.test/ok)"
docker exec "$NRP" sh -c 'test -s /var/log/nrp/coraza/audit.log' || fail "Coraza-Audit-Log ist leer"
# Host ohne WAF wird nicht gefiltert.
nrp host add plain.e2e.test -i backend -p 80 --wait >/dev/null || fail "zweiter Host"
expect "XSS ohne WAF" 200 "$(https plain.e2e.test -o /dev/null -w '%{http_code}' 'https://plain.e2e.test/?q=%3Cscript%3Ealert(1)%3C/script%3E')"

step "Defekte WAF-Regeln werden abgelehnt, die alte Konfiguration bleibt aktiv"
gen_before="$(nrp status -o json | grep -o '"generation": *[0-9]*' | grep -o '[0-9]*$')"
printf 'SecRule ARGS "@rx (" "id:1000001,phase:2,deny"\n' | nrpi waf rules set --file - >/dev/null
sleep 4
st="$(nrp status)"
contains "$st" "Letzter Fehler" "defekte Regel erzeugt keinen Fehler im Status"
expect "Generation nach defekter Regel" "$gen_before" "$(nrp status -o json | grep -o '"generation": *[0-9]*' | grep -o '[0-9]*$')"
expect "Dienst trotz defekter Regel" 200 "$(https app.e2e.test -o /dev/null -w '%{http_code}' https://app.e2e.test/ok)"
contains "$(nrp render generations)" "rejected" "abgelehnte Generation fehlt in der Historie"
# Gueltige Anpassung: Regel 941100 (XSS libinjection) usw. bleiben, eigene Ausnahme vor den Regeln.
printf 'SecRule REQUEST_URI "@beginsWith /healthz" "id:1000002,phase:1,pass,nolog,ctl:ruleEngine=Off"\n' | nrpi waf rules set --file - >/dev/null
for i in $(seq 1 30); do
  c="$(https app.e2e.test -o /dev/null -w '%{http_code}' 'https://app.e2e.test/healthz?q=%3Cscript%3Ealert(1)%3C/script%3E')"; [ "$c" = 200 ] && break; sleep 0.5
done
expect "eigene WAF-Ausnahme" 200 "$c"
expect "WAF blockiert weiterhin" 403 "$(https app.e2e.test -o /dev/null -w '%{http_code}' "$XSS")"

# ── 3. REST-API ─────────────────────────────────────────────────────────────
step "REST-API: mTLS, Rollen, ETag, Audit"
nrp ca show > "$WORK/ca.crt"
nrp client issue e2e-admin --role admin > "$WORK/admin.pem"
nrp client issue e2e-viewer --role viewer > "$WORK/viewer.pem"
for f in ca.crt admin.pem viewer.pem; do put "$WORK/$f"; done
API="https://nrp.e2e.test:8443/api/v1"
api() { local who="$1"; shift; kurl --resolve "nrp.e2e.test:8443:$NRP_IP" --cacert /w/ca.crt --cert "/w/$who.pem" "$@"; }
expect "API ohne Client-Zertifikat" 000 "$(kurl --resolve "nrp.e2e.test:8443:$NRP_IP" --cacert /w/ca.crt -o /dev/null -w '%{http_code}' "$API/hosts" 2>/dev/null || true)"
contains "$(api viewer "$API/hosts")" '"fqdn":"app.e2e.test"' "GET /hosts als viewer"
expect "viewer darf nicht schreiben" 403 "$(api viewer -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -d '{"mode":"Off"}' "$API/waf")"
etag="$(api admin -D - -o /dev/null "$API/hosts/plain.e2e.test" | tr -d '\r' | awk 'tolower($1)=="etag:" {print $2}')"
[ -n "$etag" ] || fail "ETag fehlt"
PATCH=(-X PATCH -H 'Content-Type: application/merge-patch+json' -d '{"websockets":true}')
expect "PATCH ohne If-Match" 428 "$(api admin -o /dev/null -w '%{http_code}' "${PATCH[@]}" "$API/hosts/plain.e2e.test")"
expect "PATCH mit veraltetem ETag" 412 "$(api admin -o /dev/null -w '%{http_code}' "${PATCH[@]}" -H 'If-Match: "999"' "$API/hosts/plain.e2e.test")"
expect "PATCH mit ETag" 200 "$(api admin -o /dev/null -w '%{http_code}' "${PATCH[@]}" -H "If-Match: $etag" "$API/hosts/plain.e2e.test")"
for i in $(seq 1 20); do
  nrp render show --file http.d/host-plain.e2e.test.conf | grep -q 'Connection $connection_upgrade' && break; sleep 0.5
  [ "$i" = 20 ] && fail "API-Aenderung wurde nicht gerendert"
done
contains "$(api admin "$API/audit/verify")" '"ok":true' "Audit-Kette"
contains "$(api admin "$API/audit?actor=e2e-admin&limit=5")" '"action":"host.update"' "API-Aenderung steht nicht im Audit-Log"
contains "$(api admin "$API/audit?actor=e2e-viewer&limit=5")" '"result":"denied"' "verweigerter Zugriff steht nicht im Audit-Log"
contains "$(docker logs "$NRP" 2>&1 | grep '"msg":"audit"' | tail -200)" '"action":"host.update"' "Audit-Export nach stdout fehlt"
nrp client revoke e2e-viewer >/dev/null
expect "widerrufener Client" 401 "$(api viewer -o /dev/null -w '%{http_code}' "$API/hosts")"
contains "$(kurl "http://$NRP_IP:9100/metrics")" 'nrp_certificate_not_after_seconds{fqdn="app.e2e.test"}' "Metriken"

# ── 4. Betrieb ──────────────────────────────────────────────────────────────
step "Rollback und erneutes Anwenden"
cur="$(nrp status -o json | grep -o '"generation": *[0-9]*' | grep -o '[0-9]*$')"
prev="$(nrp render generations -o json | grep -B8 '"status": "applied"' | grep -o '"id": *[0-9]*' | grep -o '[0-9]*$' | grep -vx "$cur" | head -1)"
[ -n "$prev" ] || fail "keine fruehere Generation fuer den Rollback gefunden"
nrp render rollback "$prev" >/dev/null || fail "render rollback $prev"
contains "$(nrp status)" "Rollback aktiv" "Rollback wird im Status nicht angezeigt"
nrp render show --file http.d/host-plain.e2e.test.conf | grep -q 'connection_upgrade' && fail "Rollback hat die Konfiguration nicht zurueckgesetzt"
expect "Dienst nach Rollback" 200 "$(https app.e2e.test -o /dev/null -w '%{http_code}' https://app.e2e.test/ok)"
nrp render apply >/dev/null || fail "render apply"
nrp render show --file http.d/host-plain.e2e.test.conf | grep -q 'connection_upgrade' || fail "render apply hat den DB-Stand nicht angewendet"

step "Defekter Host geht in Quarantaene, die uebrigen bleiben erreichbar"
nrp host add broken.e2e.test -i does-not-resolve.invalid -p 80 --wait >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  nrp host show broken.e2e.test | grep -q "nginx -t" && break; sleep 1
  [ "$i" = 30 ] && fail "defekter Host wurde nicht als error markiert: $(nrp host show broken.e2e.test)"
done
nrp host add after.e2e.test -i backend -p 80 --wait >/dev/null || fail "Host nach defektem Host"
contains "$(https after.e2e.test https://after.e2e.test/after)" "GET /after" "Aenderungen nach defektem Host werden nicht angewendet"
nrp host set broken.e2e.test -i backend >/dev/null
for i in $(seq 1 30); do
  c="$(https broken.e2e.test -o /dev/null -w '%{http_code}' https://broken.e2e.test/ 2>/dev/null || true)"; [ "$c" = 200 ] && break; sleep 1
done
expect "reparierter Host" 200 "$c"

step "Offline-Modus ist gesperrt, solange der Dienst laeuft; Backup; Audit"
out="$(nrp --offline host list 2>&1 || true)"
contains "$out" "ohne --offline verwenden" "Offline-Modus trotz laufendem Dienst"
contains "$(nrp backup --out e2e.db)" "/var/lib/nrp/backups/e2e.db" "Backup"
contains "$(nrp audit verify)" "intakt" "Audit-Kette"

# ── 5. Neustart ─────────────────────────────────────────────────────────────
step "Container neu erzeugen: tmpfs leer, Zustand kommt aus der DB"
serial_before="$(nrp cert show app.e2e.test --pem | docker exec -i "$P-curl" sh -c 'cat > /w/before.pem; sha256sum /w/before.pem | cut -c1-16')"
docker rm -f "$NRP" >/dev/null
start_nrp
for i in $(seq 1 20); do
  c="$(https app.e2e.test -o /dev/null -w '%{http_code}' https://app.e2e.test/ 2>/dev/null || true)"; [ "$c" = 200 ] && break; sleep 0.5
done
contains "$(https app.e2e.test https://app.e2e.test/again)" "GET /again" "Proxy nach Neustart"
expect "WAF nach Neustart" 403 "$(https app.e2e.test -o /dev/null -w '%{http_code}' "$XSS")"
expect "Zertifikat unveraendert" "$serial_before" "$(nrp cert show app.e2e.test --pem | docker exec -i "$P-curl" sh -c 'sha256sum | cut -c1-16')"
contains "$(api admin "$API/hosts/app.e2e.test")" '"status":"active"' "API mit bestehendem Client-Zertifikat nach Neustart"
contains "$(nrp audit verify)" "intakt" "Audit-Kette nach Neustart"

# ── 6. Erneuerung, Offline-Notfall ──────────────────────────────────────────
step "Erneuerung laedt das neue Zertifikat in nginx"
fp() { docker exec "$P-curl" sh -c "curl -skv --resolve app.e2e.test:443:$NRP_IP https://app.e2e.test/ -o /dev/null 2>&1 | grep -i 'start date:'; echo | true"; }
served_before="$(https app.e2e.test -o /dev/null -w '%{certs}' https://app.e2e.test/ | sha256sum | cut -c1-16)"
sleep 1
nrp cert renew app.e2e.test --wait >/dev/null || fail "cert renew --wait"
for i in $(seq 1 30); do
  served_after="$(https app.e2e.test -o /dev/null -w '%{certs}' https://app.e2e.test/ | sha256sum | cut -c1-16)"
  [ "$served_after" != "$served_before" ] && break; sleep 0.5
done
[ "$served_after" != "$served_before" ] || fail "nginx liefert nach der Erneuerung noch das alte Zertifikat aus"

step "Notfall: nrpd gestoppt, nginx proxyt weiter, CLI arbeitet offline"
docker exec "$NRP" /command/s6-svc -wD -d /run/service/nrpd
expect "Datenebene ohne nrpd" 200 "$(https app.e2e.test -o /dev/null -w '%{http_code}' https://app.e2e.test/ok)"
contains "$(nrp --offline host list)" "app.e2e.test" "Offline-Liste"
nrp --offline host set plain.e2e.test --no-websockets >/dev/null || fail "Offline-Aenderung"
nrp --offline render apply >/dev/null || fail "Offline render apply"
nrp --offline render show --file http.d/host-plain.e2e.test.conf | grep -q 'connection_upgrade' && fail "Offline-Aenderung nicht gerendert"
contains "$(nrp --offline audit list --limit 3)" "offline:uid=0" "Offline-Aktion steht nicht im Audit-Log"
docker exec "$NRP" /command/s6-svc -wu -u /run/service/nrpd
for i in $(seq 1 30); do nrp health >/dev/null 2>&1 && break; sleep 1; [ "$i" = 30 ] && fail "nrpd startet nicht wieder"; done
contains "$(nrp audit verify)" "intakt" "Audit-Kette nach Offline-Betrieb"
nrp host remove after.e2e.test >/dev/null
for i in $(seq 1 20); do
  c="$(https after.e2e.test -o /dev/null -w '%{http_code}' https://after.e2e.test/ 2>/dev/null || true)"; [ "$c" = 000 ] && break; sleep 0.5
done
expect "entfernter Host" 000 "$c"

echo "E2E-API OK ($IMAGE, $STEP Schritte)"
