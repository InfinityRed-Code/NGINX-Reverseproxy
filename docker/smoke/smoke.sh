#!/bin/sh
# Smoke-Test für den Image-Build: startet nginx mit Coraza + CRS (SecRuleEngine On)
# und prüft, dass eine harmlose Anfrage 200 und eine XSS-Payload 403 liefert.
# Passen nginx, libcoraza oder CRS nicht zusammen, scheitert der Build.
set -eu

CONF=/usr/share/nrp/smoke/nginx.conf
DIR=/tmp/nrp-smoke

cleanup() {
  [ -f "$DIR/nginx.pid" ] && kill "$(cat "$DIR/nginx.pid")" 2>/dev/null || true
  sleep 1
  rm -rf "$DIR"
}
trap cleanup EXIT

mkdir -p "$DIR"
chown nginx:nginx "$DIR"

nginx -t -c "$CONF"
nginx -c "$CONF"

# Statuscode per bash /dev/tcp holen (die Runtime enthält bewusst kein curl).
status() {
  bash -c '
    exec 3<>/dev/tcp/127.0.0.1/18080 || exit 1
    printf "GET %s HTTP/1.0\r\nHost: smoke.test\r\nUser-Agent: nrp-smoke\r\nAccept: */*\r\n\r\n" "$1" >&3
    read -t 20 -r _ code _ <&3 || exit 1
    echo "$code"
  ' _ "$1"
}

ok=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  ok="$(status / 2>/dev/null || true)"
  [ "$ok" = "200" ] && break
  sleep 1
done
blocked="$(status '/?q=%3Cscript%3Ealert(1)%3C/script%3E' 2>/dev/null || true)"

echo "smoke: harmlose Anfrage -> ${ok:-keine Antwort}, XSS-Payload -> ${blocked:-keine Antwort}"
if [ "$ok" != "200" ] || [ "$blocked" != "403" ]; then
  echo "smoke: FEHLGESCHLAGEN (erwartet 200 / 403)" >&2
  echo "--- error.log" >&2
  cat "$DIR/error.log" >&2 || true
  exit 1
fi
echo "smoke: OK"
