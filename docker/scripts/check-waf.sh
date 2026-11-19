#!/bin/sh
# nrp-check-waf <coraza-rules-file> [timeout-sekunden]
#
# Prüft, ob Coraza die Regelkette wirklich laden kann. Nötig, weil `nginx -t` die
# Regeln NICHT validiert: libcoraza wird erst im Worker per dlopen() geladen. Eine
# fehlerhafte Regeldatei besteht `nginx -t`, und nach dem Reload beenden sich alle
# neuen Worker mit "fatal code 2 and cannot be respawned" -> Totalausfall.
#
# Startet dazu einen kurzlebigen Einzelprozess-nginx (master_process off) als User
# nginx mit einem Unix-Socket-Listener und wertet dessen error.log aus.
#   Exit 0: Regeln geladen      Exit 1: Fehler (Coraza-Meldung auf stderr)
set -eu

RULES="${1:?usage: nrp-check-waf <coraza-rules-file> [timeout]}"
TIMEOUT="${2:-30}"
[ -r "$RULES" ] || { echo "nrp-check-waf: $RULES nicht lesbar" >&2; exit 1; }

DIR="$(mktemp -d /tmp/nrp-check-waf.XXXXXX)"
PID=""
RUNAS=""
cleanup() {
  if [ -n "$PID" ]; then
    # Der Testprozess läuft als nginx. Ohne CAP_KILL darf root ihn nicht signalisieren,
    # deshalb das Signal ebenfalls als nginx senden.
    # (`kill` ist ein Shell-Builtin, daher über `sh -c`.)
    $RUNAS sh -c "kill $PID" 2>/dev/null || kill "$PID" 2>/dev/null || true
    n=0
    while [ -d "/proc/$PID" ] && [ "$n" -lt 25 ]; do n=$((n + 1)); sleep 0.2; done
    if [ -d "/proc/$PID" ]; then
      $RUNAS sh -c "kill -9 $PID" 2>/dev/null || kill -9 "$PID" 2>/dev/null || true
    fi
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$DIR"
}
trap cleanup EXIT

cat > "$DIR/nginx.conf" <<EOF
daemon off;
master_process off;
pid $DIR/nginx.pid;
error_log $DIR/error.log notice;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path $DIR/client_temp;
    proxy_temp_path $DIR/proxy_temp;
    server {
        listen unix:$DIR/check.sock;
        coraza on;
        coraza_rules_file $RULES;
    }
}
EOF

if [ "$(id -u)" = "0" ]; then
  chown -R nginx:nginx "$DIR"
  RUNAS="/command/s6-setuidgid nginx"
fi

$RUNAS nginx -c "$DIR/nginx.conf" >"$DIR/stderr.log" 2>&1 &
PID=$!

i=0
while [ "$i" -lt $((TIMEOUT * 5)) ]; do
  if grep -q 'coraza: WAFs initialized' "$DIR/error.log" 2>/dev/null; then
    grep -o 'coraza: loc WAF initialized with [0-9]* rules' "$DIR/error.log" | tail -n1 || true
    exit 0
  fi
  if [ ! -d "/proc/$PID" ]; then
    break
  fi
  i=$((i + 1))
  sleep 0.2
done

echo "nrp-check-waf: Coraza konnte die Regeln nicht laden ($RULES)" >&2
grep -E '\[(error|emerg|alert|crit)\]' "$DIR/error.log" 2>/dev/null | cut -c1-2000 >&2 || true
cat "$DIR/stderr.log" >&2 2>/dev/null || true
exit 1
