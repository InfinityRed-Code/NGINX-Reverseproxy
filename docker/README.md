# NRP-Image

nginx (aus Quellcode, Coraza statisch einkompiliert) + libcoraza + OWASP CRS + `nrp` unter
s6-overlay. Hintergründe: `rewrite.md`, Abschnitt 4.

## Lokal bauen und testen

```bash
# Build-Kontext ist das Repo-Root
docker build $(sed -e '/^#/d' -e '/^$/d' -e 's/^/--build-arg /' versions.env) \
  -f docker/Dockerfile -t nrp:dev .

# E2E unter den Härtungsoptionen aus deploy/compose.yaml
bash docker/tests/e2e.sh nrp:dev
```

Der Build bricht ab, wenn

- die GPG-Signatur oder SHA256 des nginx-Tarballs nicht passt,
- ein Patch unter `patches/` sich nicht anwenden lässt oder keinen Kopf hat,
- der Smoke-Test scheitert (`docker/smoke/smoke.sh`: echter Worker mit Coraza + CRS,
  harmlose Anfrage → 200, XSS-Payload → 403).

## Layout

| Pfad | Zweck |
|---|---|
| `Dockerfile` | Stages: build-base → libcoraza → nginx → crs → s6 → nrp → runtime |
| `nginx.conf` | Statische Basis-Config; alles Dynamische unter `/run/nrp/render/current/http.d/` |
| `scripts/configure-nginx.sh` | `./configure`-Optionen (Abschnitt 4.3) |
| `scripts/apply-patches.sh` | Patch-Mechanismus (Abschnitt 4.5, siehe `patches/README.md`) |
| `scripts/check-waf.sh` | Im Image als `nrp-check-waf`: prüft, ob Coraza eine Regelkette laden kann |
| `keys/nginx/` | GPG-Schlüssel der nginx-Release-Signierer (nginx.org/keys) |
| `s6/` | s6-rc-Dienste `init-nrp` (oneshot), `nginx`, `nrpd` (longrun, voneinander unabhängig) |
| `smoke/` | Smoke-Test-Config für den Build |
| `tests/e2e.sh` | E2E gegen ein fertiges Image |

## Wichtig: `nginx -t` prüft keine Coraza-Regeln

libcoraza ist eine Go-Bibliothek und wird erst **im Worker** per `dlopen()` geladen. Eine
fehlerhafte Regeldatei besteht `nginx -t`; nach dem Reload beenden sich dann alle neuen
Worker (`exited with fatal code 2 and cannot be respawned`) – der Proxy steht. Vor jedem
Reload mit geänderten Regeln deshalb:

```bash
nrp-check-waf /run/nrp/render/gen-<N>/coraza/main.conf    # Exit 0 = ladbar
```

Weitere Eigenheiten:

- Coraza nutzt Go-RE2: keine Lookaheads. Das v2-Muster `SecAuditLogRelevantStatus "^(?:5|4(?!04))"`
  ist ungültig, Ersatz: `"^(?:5|4(?:0[0-35-9]|[1-9][0-9]))"`.
- Das Verzeichnis von `SecAuditLog` muss existieren und dem User `nginx` gehören (das Log wird
  im Worker geöffnet). `init-nrp` stellt das für `/var/log/nrp/coraza` sicher.
- `return` in einer `location` läuft vor Coraza (Rewrite-Phase) und wird nicht geprüft;
  `proxy_pass` schon.

## Capabilities

Verifiziert mit `docker/tests/e2e.sh` (read-only Root, `no-new-privileges`, Volumes gehören UID 1000):

| Capability | Nötig für | Ohne |
|---|---|---|
| `CHOWN` | nginx-Master setzt Eigentümer der Temp-Verzeichnisse; `init-nrp` für Coraza-Log | `chown(...) failed`, Container startet nicht |
| `SETUID`, `SETGID` | Worker laufen als `nginx` | keine Worker |
| `DAC_OVERRIDE` | root schreibt in Bind-Mounts, die dem Host-User gehören; liest `master.key` (0600, Host-User) | `master key unreadable`, keine Logs/DB |
| `KILL` | **nicht gesetzt.** Ohne sie darf root Prozesse des Users `nginx` nicht signalisieren | Reload/Reopen/Stop funktionieren trotzdem (Master steuert Worker über den Channel); nur ein `SIGKILL` des Masters an hängende Worker entfällt. Bei Bedarf ergänzen. |
| `NET_BIND_SERVICE` | Ports 80/443 | unter Docker ≥ 20.10 nicht nötig (`ip_unprivileged_port_start=0`), für andere Runtimes belassen |
| `NET_ADMIN` | WireGuard (`wg0`, Peers, Routen) | nur mit `NRP_WIREGUARD_ENABLED=true` |

`FOWNER` wird nicht benötigt. `DAC_OVERRIDE` kann entfallen, wenn `data/` und
`secrets/master.key` auf dem Host `root` gehören.

`/run` muss als tmpfs **mit `exec`** gemountet sein (`/run:exec,mode=0755`), sonst startet
s6-overlay nicht.
