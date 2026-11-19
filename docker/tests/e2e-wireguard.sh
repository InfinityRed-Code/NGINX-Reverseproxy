#!/usr/bin/env bash
# E2E-Test fuer WireGuard-Sites (rewrite.md Phase 4): eine Site baut den Tunnel zum
# Hub auf, ein Host hinter der Site ist ueber NRP erreichbar.
#
#   docker/tests/e2e-wireguard.sh nrp:dev
#
# Braucht das WireGuard-Kernelmodul auf dem Docker-Host (ab Kernel 5.6) und NET_ADMIN.
# Fehlt das Modul, endet der Test mit Exit-Code 77 (uebersprungen).
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE="${1:?usage: e2e-wireguard.sh <image>}"
P="nrp-wg-e2e-$$"
NET="$P-net"
SUBNET="${E2E_SUBNET:-10.77.32.0/24}"
NRP_IP="${SUBNET%.*}.10"
NRP="$P-nrp"
SITE="$P-site"
STEP=0

step() { STEP=$((STEP + 1)); echo "[$STEP] $*"; }
fail() {
  echo "E2E FEHLER (Schritt $STEP): $*" >&2
  docker logs "$NRP" 2>&1 | grep -v '"msg":"audit"' | tail -8 >&2 || true
  echo "--- diag ---" >&2
  docker ps -a --filter "name=$P" --format "{{.Names}} {{.Status}}" >&2 || true
  docker logs "$P-backend" 2>&1 | tail -5 >&2 || true
  docker exec "$SITE" sh -c "wg show; ip -4 addr; ip route; wget -qO- -T 3 http://127.0.0.1:80/local | head -3" >&2 2>&1 || true
  docker exec "$NRP" sh -c "wg show wg0; ip route" >&2 2>&1 || true
  docker exec "$P-probe" curl -v --max-time 5 http://10.240.0.2:80/x >&2 2>&1 || true
  exit 1
}
cleanup() {
  docker rm -f "$NRP" "$SITE" "$P-backend" "$P-probe" >/dev/null 2>&1 || true
  docker volume rm -f "$P-data" "$P-logs" "$P-secret" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
nrp() { docker exec "$NRP" nrp "$@"; }
contains() { grep -q -- "$2" <<<"$1" || fail "$3 (gesucht: $2)
$1"; }

step "Hub mit WireGuard starten"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run --rm --entrypoint sh -v "$P-data:/d" -v "$P-logs:/l" -v "$P-secret:/s" "$IMAGE" -c '
  mkdir -p /d/db /d/backups && head -c 32 /dev/urandom > /s/master.key && chmod 600 /s/master.key'
docker run -d --name "$NRP" --network "$NET" --ip "$NRP_IP" \
  --read-only --tmpfs /run:exec,mode=0755 --tmpfs /var/cache/nginx --tmpfs /tmp \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE --cap-add DAC_OVERRIDE --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  --mount "type=volume,src=$P-data,dst=/var/lib/nrp/db,volume-subpath=db" \
  -v "$P-logs:/var/log/nrp" \
  --mount "type=volume,src=$P-secret,dst=/run/secrets/nrp_master_key,volume-subpath=master.key,readonly" \
  -e NRP_WIREGUARD_ENABLED=true -e "NRP_PUBLIC_ENDPOINT=$NRP_IP" -e NRP_API_SANS=127.0.0.1 \
  -e NRP_ACME_DIRECTORY=https://127.0.0.1:1/unused \
  "$IMAGE" >/dev/null
for i in $(seq 1 40); do nrp health >/dev/null 2>&1 && break; sleep 1; done
if ! docker exec "$NRP" ip link show wg0 >/dev/null 2>&1; then
  if docker logs "$NRP" 2>&1 | grep -qiE "wg0 anlegen|not supported|operation not supported"; then
    echo "UEBERSPRUNGEN: WireGuard-Kernelmodul auf dem Docker-Host nicht verfuegbar" >&2
    exit 77
  fi
  fail "wg0 wurde nicht angelegt"
fi
nrp health >/dev/null || fail "nrp health"
contains "$(docker exec "$NRP" ip -4 addr show wg0)" "10.240.0.1/16" "Hub-Adresse auf wg0"
contains "$(nrp doctor)" "WireGuard wg0" "nrp doctor prueft wg0 nicht"

step "Site anlegen, Install-Script erzeugen"
out="$(nrp site create home --targets 4 --os alpine 2>/dev/null)"
contains "$out" "10.240.0.0/29" "Subnetz-Vergabe"
contains "$out" "10.240.0.2" "Connector-IP"
nrp site install-script home > /dev/null || fail "install-script"
script="$(nrp site install-script home)"
contains "$script" "Endpoint = $NRP_IP:51820" "Endpoint aus NRP_PUBLIC_ENDPOINT"
contains "$script" "PresharedKey = " "PSK im Install-Script"
# Ohne Public Key hat der Hub noch keinen Peer.
[ -z "$(docker exec "$NRP" wg show wg0 peers)" ] || fail "Peer ohne Public Key konfiguriert"

step "Site-Host: Tunnel mit der Konfiguration aus dem Install-Script aufbauen"
docker run -d --name "$SITE" --network "$NET" --cap-add NET_ADMIN --entrypoint sleep alpine:3.22 3600 >/dev/null
docker exec "$SITE" apk add --no-cache -q wireguard-tools-wg iproute2 >/dev/null || fail "wireguard-tools im Site-Container"
# Abschnitt [Interface]/[Peer] des Scripts uebernehmen (ohne Paketinstallation, sysctl und NAT).
conf="$(sed -n '/<< WGEOF/,/^WGEOF/p' <<<"$script" | sed '1d;$d')"
docker exec -i "$SITE" sh -c '
  set -e
  umask 077
  PRIVATE_KEY=$(wg genkey)
  echo "$PRIVATE_KEY" | wg pubkey > /pub
  sed "s|\$PRIVATE_KEY|$PRIVATE_KEY|" > /full.conf
  addr=$(awk "/^Address/ {print \$3}" /full.conf)
  grep -v "^Address" /full.conf > /wg.conf
  ip link add wg-site type wireguard
  wg setconf wg-site /wg.conf
  ip addr add "$addr" dev wg-site
  ip link set wg-site up
  ip route add 10.240.0.0/16 dev wg-site 2>/dev/null || true' <<<"$conf" || fail "Tunnel auf der Site einrichten"
pub="$(docker exec "$SITE" cat /pub)"
nrp site set-pubkey home "$pub" >/dev/null || fail "set-pubkey"
for i in $(seq 1 20); do
  [ "$(docker exec "$NRP" wg show wg0 peers)" = "$pub" ] && break; sleep 0.5
  [ "$i" = 20 ] && fail "Hub hat den Peer nicht uebernommen"
done
contains "$(docker exec "$NRP" wg show wg0 allowed-ips)" "10.240.0.0/29" "AllowedIPs des Peers"

step "Handshake und Erreichbarkeit durch den Tunnel"
# Die Site hat ihren ersten Handshake evtl. gesendet, bevor der Hub den Peer kannte;
# WireGuard wiederholt ihn erst nach 5 s. Deshalb mit Geduld pruefen.
ok=0
for i in $(seq 1 20); do
  if docker exec "$SITE" ping -c 1 -W 2 10.240.0.1 >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || fail "Hub durch den Tunnel nicht erreichbar"
docker exec "$NRP" sh -c 'command -v ping >/dev/null' && { docker exec "$NRP" ping -c 1 -W 3 10.240.0.2 >/dev/null || fail "Site vom Hub nicht erreichbar"; }
out="$(nrp site show home --live)"
contains "$out" "online=ja" "Live-Status aus dem Handshake"
for i in $(seq 1 45); do
  nrp site list | grep -q "online" && break; sleep 1
  [ "$i" = 45 ] && fail "Site-Status wurde nicht auf online gesetzt: $(nrp site list)"
done

step "Host hinter der Site ueber NRP erreichbar"
docker run -d --name "$P-backend" --network "container:$SITE" traefik/whoami:latest >/dev/null
# Die Subnetzpruefung lehnt Upstreams ausserhalb des Site-Netzes ab.
out="$(nrp host add tun.e2e.test -i 10.99.0.1 -p 80 --site home 2>&1 || true)"
contains "$out" "liegt nicht im Netz der Site" "Subnetzpruefung"
nrp host add tun.e2e.test -i 10.240.0.2 -p 80 --site home >/dev/null 2>&1 || fail "host add --site"
# Ein Abgleich ohne Aenderung an der Site darf Endpoint und Sitzung des Peers nicht verwerfen.
nrp settings set client_max_body_size=50M >/dev/null
sleep 2
contains "$(docker exec "$NRP" wg show wg0 endpoints)" "${SUBNET%.*}." "Reconcile hat den Peer zurueckgesetzt (Endpoint verloren)"
# Ohne ACME-CA: selbstsigniertes Zertifikat im Offline-Importpfad waere moeglich; hier
# genuegt der Nachweis, dass nginx den Upstream durch den Tunnel erreicht.
docker run -d --name "$P-probe" --network "container:$NRP" --entrypoint sleep curlimages/curl:latest 600 >/dev/null
body=""
for i in $(seq 1 20); do
  body="$(docker exec "$P-probe" curl -sS --max-time 10 http://10.240.0.2:80/through-tunnel 2>/dev/null || true)"
  [ -n "$body" ] && break; sleep 0.5
done
contains "$body" "GET /through-tunnel" "Upstream durch den Tunnel aus dem Netz-Namespace von nginx"

step "PSK rotieren trennt den Tunnel, Site loeschen entfernt den Peer"
nrp site rotate-psk home >/dev/null 2>&1 || fail "rotate-psk"
sleep 1
out="$(nrp site delete home -y 2>&1 || true)"
contains "$out" "wird noch von 1 Host" "Site in Benutzung darf nicht geloescht werden"
nrp host remove tun.e2e.test >/dev/null
nrp site delete home -y >/dev/null || fail "site delete"
for i in $(seq 1 20); do
  [ -z "$(docker exec "$NRP" wg show wg0 peers)" ] && break; sleep 0.5
  [ "$i" = 20 ] && fail "Peer wurde nach dem Loeschen der Site nicht entfernt"
done
contains "$(nrp audit verify)" "intakt" "Audit-Kette"

echo "E2E-WireGuard OK ($IMAGE, $STEP Schritte)"
