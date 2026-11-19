#!/usr/bin/env bash
# E2E-Test gegen ein fertig gebautes NRP-Image (CI und lokal):
#
#   docker/tests/e2e.sh nrp:dev
#
# Prüft unter den Härtungsoptionen aus deploy/compose.yaml (read_only, cap_drop ALL,
# tmpfs, no-new-privileges) und mit Bind-Mounts, die einem Nicht-root-User gehören:
#   1. s6 startet, init-nrp, nginx und nrpd laufen
#   2. nginx enthält das Coraza-Modul, nur die gewünschten Module sind gebaut
#   3. WAF: harmlose Anfrage 200, XSS-Payload 403 (Coraza + CRS, SecRuleEngine On)
#   4. `nrp doctor` und `nrp health` sind grün            (E2E_SKIP_NRP=1 überspringt das)
#
# E2E_CAPS überschreibt die Capability-Liste (Standard = deploy/compose.yaml ohne NET_ADMIN).
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash unter Windows: Containerpfade nicht umschreiben

IMAGE="${1:?usage: e2e.sh <image>}"
NAME="nrp-e2e-$$"
CAPS="${E2E_CAPS:-CHOWN SETUID SETGID NET_BIND_SERVICE DAC_OVERRIDE}"
VOL_DATA="${NAME}-data"
VOL_LOGS="${NAME}-logs"
VOL_SECRET="${NAME}-secret"

fail() { echo "E2E FEHLER: $*" >&2; docker logs "$NAME" 2>&1 | tail -40 >&2 || true; exit 1; }
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL_DATA" "$VOL_LOGS" "$VOL_SECRET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Volumes wie auf einem echten Host vorbereiten: Verzeichnisse und Master-Key gehören
# UID 1000 (der Admin, der `mkdir data` ausgeführt hat), Key mit Modus 0600.
docker run --rm --entrypoint sh \
  -v "$VOL_DATA:/d" -v "$VOL_LOGS:/l" -v "$VOL_SECRET:/s" "$IMAGE" -c '
    mkdir -p /d/db /d/backups
    head -c 32 /dev/urandom > /s/master.key
    chmod 600 /s/master.key
    chown -R 1000:1000 /d /l /s
    chmod 755 /d /d/db /d/backups /l /s'

cap_args=(--cap-drop ALL)
for c in $CAPS; do cap_args+=(--cap-add "$c"); done

docker run -d --name "$NAME" \
  --read-only \
  --tmpfs /run:exec,mode=0755 --tmpfs /var/cache/nginx --tmpfs /tmp \
  "${cap_args[@]}" \
  --security-opt no-new-privileges:true \
  --mount "type=volume,src=$VOL_DATA,dst=/var/lib/nrp/db,volume-subpath=db" \
  --mount "type=volume,src=$VOL_DATA,dst=/var/lib/nrp/backups,volume-subpath=backups" \
  -v "$VOL_LOGS:/var/log/nrp" \
  --mount "type=volume,src=$VOL_SECRET,dst=/run/secrets/nrp_master_key,volume-subpath=master.key,readonly" \
  -e NRP_PUBLIC_ENDPOINT=e2e.test:51820 \
  -e NRP_API_LISTEN=127.0.0.1:8443 \
  -e NRP_API_SANS=127.0.0.1 \
  -e NRP_WIREGUARD_ENABLED=false \
  "$IMAGE" >/dev/null

echo "[1/4] s6 und Dienste"
for i in $(seq 1 30); do
  if docker exec "$NAME" test -s /run/nginx.pid 2>/dev/null; then break; fi
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = "true" ] || fail "Container beendet"
  sleep 1
  [ "$i" = 30 ] && fail "nginx-PID-Datei nicht vorhanden"
done
docker exec "$NAME" sh -c 'kill -0 "$(cat /run/nginx.pid)"' || fail "nginx-Master läuft nicht"
docker exec "$NAME" /command/s6-svstat /run/service/nginx | grep -q '^up' || fail "s6: nginx nicht up"
docker exec "$NAME" /command/s6-svstat /run/service/nrpd  | grep -q '^up' || fail "s6: nrpd nicht up"
docker exec "$NAME" test -d /var/log/nrp/nginx -a -d /var/log/nrp/coraza -a -d /run/nrp \
  || fail "init-nrp hat Verzeichnisse nicht angelegt"
docker exec "$NAME" test -f /var/log/nrp/nginx/error.log || fail "nginx schreibt kein error.log im Mount"
# Worker laufen als nginx, nicht als root (kurz warten: Worker starten nach der PID-Datei)
workers_ok=0
for i in $(seq 1 10); do
  if docker exec "$NAME" sh -c '
    found=""
    for p in /proc/[0-9]*; do
      if grep -q "^nginx: worker" "$p/cmdline" 2>/dev/null; then
        uid=$(awk "/^Uid:/ {print \$2}" "$p/status" 2>/dev/null); [ "$uid" != "0" ] || exit 1; found=1
      fi
    done; [ -n "$found" ]'; then workers_ok=1; break; fi
  sleep 1
done
[ "$workers_ok" = 1 ] || fail "nginx-Worker fehlen oder laufen als root"

echo "[2/4] nginx-Build"
V="$(docker exec "$NAME" nginx -V 2>&1)"
grep -q coraza <<<"$V" || fail "Coraza-Modul fehlt in nginx -V"
for m in http_ssl_module http_v2_module http_realip_module http_stub_status_module; do
  grep -q -- "--with-$m" <<<"$V" || fail "Modul $m fehlt"
done
for m in mail stream http_v3 http_mp4 http_dav; do
  if grep -q -- "--with-$m" <<<"$V"; then fail "unerwünschtes Modul $m gebaut"; fi
done
docker exec "$NAME" nginx -t >/dev/null 2>&1 || fail "nginx -t (produktive Config) fehlgeschlagen"
docker exec "$NAME" nginx -s reload || fail "nginx -s reload fehlgeschlagen"

echo "[3/4] WAF (Coraza + CRS)"
docker exec "$NAME" sh /usr/share/nrp/smoke/smoke.sh || fail "WAF-Smoke-Test fehlgeschlagen"
# Regel-Validierung wie im Reconciler: gültige Kette ok, kaputte Regel wird erkannt
docker exec "$NAME" sh -c '
  cat > /tmp/e2e-main.conf <<EOF
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /var/log/nrp/coraza/audit.log
Include /usr/share/nrp/coreruleset/crs-setup.conf.example
Include /usr/share/nrp/coreruleset/rules/*.conf
EOF
  echo "SecRule ARGS \"@rx (\" \"id:1,deny\"" > /tmp/e2e-bad.conf
  nrp-check-waf /tmp/e2e-main.conf && ! nrp-check-waf /tmp/e2e-bad.conf 2>/dev/null' \
  || fail "nrp-check-waf: gültige Regeln abgelehnt oder kaputte akzeptiert"

echo "[4/4] nrp"
if [ "${E2E_SKIP_NRP:-0}" = "1" ]; then
  echo "      übersprungen (E2E_SKIP_NRP=1)"
else
  ok=0
  for i in $(seq 1 30); do
    if docker exec "$NAME" nrp health >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || fail "nrp health wurde nicht grün"
  docker exec "$NAME" nrp doctor || fail "nrp doctor meldet Fehler"
  docker exec "$NAME" test -S /run/nrp/nrp.sock || fail "Unix-Socket fehlt"
fi

echo "E2E OK ($IMAGE, caps: $CAPS)"
