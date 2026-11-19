# NRP v3 – Rewrite-Plan: Container, Go, REST-API, SQLite

Dieses Dokument beschreibt den Umbau von NRP (aktuell Python-CLI für Debian-Hosts) zu einem containerisierten Dienst mit REST-API, SQLite-Zustand, Audit-Log und weiterhin vollständig nutzbarer CLI per `docker exec`.

Status: Entwurf (Rev. 2: Source-Build auf debian:trixie-slim) · Basis: Stand `main` (Python, v2) · Zielversion: v3

---

## Inhalt

1. [Ziele und Nicht-Ziele](#1-ziele-und-nicht-ziele)
2. [Sprachentscheidung: Go](#2-sprachentscheidung-go)
3. [Zielarchitektur](#3-zielarchitektur)
4. [Container-Image](#4-container-image)
5. [Persistenz: SQLite und Datenlayout](#5-persistenz-sqlite-und-datenlayout)
6. [Authentifizierung und Autorisierung](#6-authentifizierung-und-autorisierung)
7. [Audit-Log](#7-audit-log)
8. [Parallelität und Reconcile-Loop](#8-parallelität-und-reconcile-loop)
9. [REST-API](#9-rest-api)
10. [CLI und CLI→API-Übersetzung](#10-cli-und-cliapi-übersetzung)
11. [Komponenten im Detail](#11-komponenten-im-detail)
12. [Template-Änderungen](#12-template-änderungen)
13. [Docker Compose](#13-docker-compose)
14. [Migration von v2](#14-migration-von-v2)
15. [Projektstruktur Go](#15-projektstruktur-go)
16. [Tests](#16-tests)
17. [Umsetzungsphasen](#17-umsetzungsphasen)
18. [Offene Punkte](#18-offene-punkte)

---

## 1. Ziele und Nicht-Ziele

### Ziele

- **Containerbetrieb**: Ein Image enthält nginx, Coraza-WAF-Modul, OWASP CRS und den NRP-Dienst. Kein `apt install`, kein Build auf dem Zielsystem.
- **REST-API** als primäre Konfigurationsschnittstelle, ausschließlich authentifiziert.
- **SQLite** als einzige Quelle der Wahrheit, gemappt in ein Host-Verzeichnis neben der `compose.yaml`.
- **Audit-Log** für jede Änderung, manipulationserkennbar.
- **Parallelisierbarkeit**: gleichzeitige API-Anfragen, parallele Zertifikatsausstellung, keine Race Conditions beim Rendern.
- **CLI bleibt vollwertig**: `docker exec -it nrp nrp …` bietet alle Funktionen, inklusive Offline-Notfallmodus, wenn der Dienst nicht läuft.
- **Datenebene unabhängig von Steuerungsebene**: Fällt der NRP-Dienst aus, proxyt nginx weiter.

### Nicht-Ziele

- Kein Ersatz von nginx durch einen eigenen Proxy.
- Keine Web-UI in v3 (die API ist so gebaut, dass eine UI später darauf aufsetzen kann).
- Kein Cluster-/HA-Betrieb mehrerer NRP-Instanzen gegen dieselbe Datenbank (SQLite ist Single-Node).
- Fail2Ban wird nicht in den Container übernommen (siehe [11.5](#115-fail2ban--crowdsec)).

---

## 2. Sprachentscheidung: Go

**Entscheidung: Go.**

| Kriterium | Go | Rust |
|---|---|---|
| Coraza-Ökosystem | Coraza, libcoraza und coraza-caddy sind Go. Bei Problemen ist der Code in derselben Sprache lesbar. | Kein nativer Coraza-Pfad. |
| WireGuard-Steuerung | `golang.zx2c4.com/wireguard/wgctrl` (vom WireGuard-Autor), direkt per Netlink | Bindings existieren, weniger verbreitet |
| ACME | `go-acme/lego`: ausgereift, unterstützt ARI, HTTP-01-Webroot, Staging | `instant-acme`: gut, aber schmaler |
| SQLite ohne cgo | `modernc.org/sqlite` (pure Go) → statisches Binary | `rusqlite` benötigt C-Kompilat (gebündelt, unproblematisch) |
| Templates | `text/template` in der Standardbibliothek | `tera`/`askama` |
| Ops-Tooling (CLI, API, Prozesse, Signale) | Sehr reifer Standard (cobra, chi, slog) | Gut, höhere Lernkurve |
| Team-Einstieg aus Python | Schnell | Deutlich langsamer |

Rust wäre die bessere Wahl, wenn nginx selbst ersetzt werden sollte (z. B. auf Basis von Pingora). Für einen Control-Plane-Dienst, der Dateien rendert, Prozesse signalisiert und Netlink anspricht, bringt Rust hier keinen Vorteil, der die höhere Entwicklungszeit rechtfertigt.

**Mindestversion:** Go ≥ 1.24 (von libcoraza gefordert). Beim Projektstart die aktuelle stabile Go-Version pinnen.

---

## 3. Zielarchitektur

```
                      Internet
                         │ 80/443 TCP, 51820 UDP
┌────────────────────────▼──────────────────────────────────────┐
│ Container "nrp"                                              │
│                                                              │
│  s6-overlay (PID 1)                                          │
│   ├── longrun: nginx  ── Datenebene (Proxy, TLS, Coraza)     │
│   └── longrun: nrpd   ── Steuerungsebene                     │
│          ├─ REST-API (mTLS, :8443)                           │
│          ├─ Unix-Socket /run/nrp/nrp.sock (lokale CLI)       │
│          ├─ Reconciler (DB → nginx-Config → nginx -t → HUP)  │
│          ├─ ACME-Worker-Pool (lego, HTTP-01)                 │
│          ├─ WireGuard (wgctrl/netlink → wg0)                 │
│          └─ SQLite (WAL)                                     │
│                                                              │
│  tmpfs: /run/nrp  (Zertifikate, gerenderte Configs, Socket)  │
└────────────┬─────────────────────────────────────────────────┘
             │ Bind-Mounts
   ./data/db/        SQLite (+ -wal, -shm)
   ./data/logs/      nginx- und Coraza-Logs
   ./secrets/        Master-Key (Docker Secret)
```

### Warum ein Container und nicht nginx + Controller getrennt?

- `nginx -t` muss mit exakt derselben Binary und denselben Modulen laufen wie der produktive nginx.
- Reload per Signal benötigt Zugriff auf den nginx-Master-Prozess.
- WireGuard: nginx muss im selben Netzwerk-Namespace wie `wg0` laufen, und `nrpd` braucht `NET_ADMIN` in genau diesem Namespace, um Peers zu verwalten.

Getrennte Container würden für alle drei Punkte geteilte Namespaces erzwingen. Der Isolationsgewinn wäre damit praktisch null, die Komplexität aber höher.

### Warum s6-overlay statt nrpd als PID 1?

Wäre `nrpd` PID 1 und Elternprozess von nginx, würde ein Absturz von `nrpd` den Container beenden und den gesamten Proxy-Traffic unterbrechen. Mit s6-overlay werden nginx und `nrpd` unabhängig überwacht:

- `nrpd` stürzt ab → s6 startet ihn neu, nginx läuft mit der letzten gültigen Config weiter.
- `docker exec nrp nrp --offline …` funktioniert, auch wenn `nrpd` dauerhaft nicht startet.

---

## 4. Container-Image

### 4.1 Basis-Entscheidung: `debian:trixie-slim`, nginx aus Quellcode

**Entscheidung:** Build- und Laufzeit-Image basieren auf **Debian 13 „trixie“**. nginx, libcoraza und coraza-nginx werden **aus Quellcode** gebaut, OpenSSL, PCRE2, zlib und glibc kommen aus Debian.

Begründung:

1. **CVE-Reaktion für nginx und Coraza liegt bei uns.** nginx.org veröffentlicht bei Sicherheitslücken meist am selben Tag eine korrigierte Version und häufig einen Patch. Mit eigenem Build kann ein Patch sofort eingespielt werden, ohne auf einen Rebuild fremder Images zu warten (siehe [4.5](#45-patch-verzeichnis)).
2. **Schnelle OS-Patches.** Die übrigen sicherheitsrelevanten Bibliotheken – vor allem OpenSSL für einen TLS-terminierenden Proxy – patcht das Debian Security Team direkt. Rocky Linux baut dagegen Red-Hat-Pakete nach und kann systembedingt nur gleich schnell oder langsamer sein als RHEL.
3. **glibc-Kompatibilität.** coraza-nginx lädt `libcoraza.so` (ein cgo-Kompilat) zur Laufzeit per `dlopen()`. Builder (`golang:<GO>-trixie`, Debian-basiert) und Runtime (`debian:trixie-slim`) haben dieselbe glibc.
4. **Kleine Angriffsfläche.** Beim eigenen Build werden nur benötigte nginx-Module einkompiliert (siehe [4.3](#43-nginx-build-konfiguration)). CVEs in nicht gebauten Modulen (z. B. mail, mp4, QUIC) betreffen uns nicht.
5. **Kontinuität.** Das bisherige Tool zielt auf Debian 13, der WAF-Build ist dort erprobt.
6. **Größe.** `debian:trixie-slim` ist etwas kleiner als `rockylinux:10-minimal` (ca. 30 vs. 40 MB komprimiert). Das ist ein Nebeneffekt, kein Entscheidungsgrund: libcoraza, das nrp-Binary und CRS machen den Großteil des Images aus.

**OpenSSL bleibt System-OpenSSL.** Ein eigenes, statisch gelinktes OpenSSL (`--with-openssl=`) würde die Reaktion auf OpenSSL-CVEs ebenfalls in unsere Hand legen, verlangt aber dediziertes Advisory-Monitoring und wird von Scannern schlechter erkannt. Neu bewerten, falls HTTP/3 benötigt wird.

**Verworfene Alternativen:**

| Basis | Grund |
|---|---|
| Offizielles `nginx`-Image | Patch-Zeitpunkt für nginx hängt an fremdem Rebuild; mitgelieferte, ungenutzte Module vergrößern die Angriffsfläche. |
| Rocky Linux 10 | Nachbau-Lag gegenüber RHEL bei OS-Patches, kein offizielles Go-Image (Go per Tarball), etwas größer. Falls RHEL-Kompatibilität vorgeschrieben wird: **UBI 10 minimal** statt Rocky, da Red Hat dort direkt patcht. |
| Wolfi (Chainguard) | Schnellste CVE-Behebung, technisch passend (glibc). Verworfen wegen Abhängigkeit von einem Anbieter; bei Bedarf neu bewerten. |
| Alpine (musl) | libcoraza/cgo auf musl weniger getestet. |
| Distroless | s6-overlay benötigt eine Shell; Notfall-Debugging per `docker exec` ist ausdrücklich gewünscht. |

### 4.2 Versions-Pinning

Alle Versionen stehen in `versions.env` und werden als Build-Argumente übergeben. Renovate hält sie aktuell (siehe [4.7](#47-build--und-update-pipeline)).

```ini
# versions.env
DEBIAN_IMAGE=debian:trixie-slim@sha256:<digest>
GO_IMAGE=golang:<1.2x>-trixie@sha256:<digest>
NGINX_VERSION=1.30.x            # nur Stable-Linie (gerade Minor-Version)
NGINX_SHA256=<sha256 des Tarballs>
LIBCORAZA_REF=<tag>             # ABI >= 1.4, von coraza-nginx v0.20 gefordert
CORAZA_NGINX_REF=v0.20.0        # upstream weiterhin experimentell
CRS_REF=v4.16.0                 # ersetzt `nrp waf enable --crs-version`
S6_OVERLAY_VERSION=<version>
S6_OVERLAY_SHA256_NOARCH=<sha256>
S6_OVERLAY_SHA256_X86_64=<sha256>
S6_OVERLAY_SHA256_AARCH64=<sha256>
```

- Basis-Images immer mit Digest gepinnt. Renovate aktualisiert den Digest, sobald Debian ein neues `trixie-slim` mit Sicherheitsupdates veröffentlicht.
- nginx-Tarball doppelt geprüft: GPG-Signatur gegen die im Repo hinterlegten nginx-Signing-Keys (`docker/keys/nginx/`) und SHA256 aus `versions.env`.
- Go-Version (Builder) ≥ 1.24. Sie betrifft auch die Sicherheit: `libcoraza.so` und `nrp` enthalten die Go-Standardbibliothek (`net/http`, `crypto/tls`). Go-Patch-Releases werden wie Sicherheitsupdates behandelt.

### 4.3 nginx-Build-Konfiguration

Coraza wird **statisch** einkompiliert (`--add-module`). Damit entfällt `load_module`, und es gibt kein Modul, das zur Binary passen muss. `libcoraza.so` wird weiterhin zur Laufzeit per `dlopen()` geladen.

Pfade entsprechen dem bisherigen Debian-Layout, damit Doku, Fehlersuche und Gewohnheiten (`nginx -T`, `/etc/nginx`) gleich bleiben. Härtungs-Flags kommen von `dpkg-buildflags` (Debian-Standard: Stack-Protector, `_FORTIFY_SOURCE`, PIE, RELRO, BIND_NOW).

```bash
./configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nrp/nginx/error.log \
  --http-log-path=/var/log/nrp/nginx/access.log \
  --pid-path=/run/nginx.pid \
  --lock-path=/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --user=nginx --group=nginx \
  --with-compat \
  --with-threads \
  --with-file-aio \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --without-http_autoindex_module \
  --without-http_ssi_module \
  --without-http_userid_module \
  --without-http_fastcgi_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --without-http_grpc_module \
  --without-http_memcached_module \
  --without-http_empty_gif_module \
  --without-http_browser_module \
  --without-mail_pop3_module \
  --without-mail_imap_module \
  --without-mail_smtp_module \
  --add-module=/src/coraza-nginx \
  --with-cc-opt="$(dpkg-buildflags --get CFLAGS) $(dpkg-buildflags --get CPPFLAGS)" \
  --with-ld-opt="$(dpkg-buildflags --get LDFLAGS)"
```

Bewusst **nicht** gebaut: `stream` (kein TCP/UDP-Proxying in v3), `mail`, `http_v3` (QUIC), `mp4`, `flv`, `dav`, `image_filter`, `xslt`, `geoip`, `perl`, `njs`. Wird später eines davon benötigt, kommt es per Flag hinzu.

`--with-compat` bleibt, damit bei Bedarf einzelne dynamische Module nachgebaut werden können, ohne nginx neu zu konfigurieren.

### 4.4 Dockerfile (Skizze)

```dockerfile
# syntax=docker/dockerfile:1.7
ARG DEBIAN_IMAGE
ARG GO_IMAGE

# ── Stage 1: Build-Basis ───────────────────────────────────────────────────
FROM ${GO_IMAGE} AS build-base
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential dpkg-dev autoconf automake libtool pkg-config \
      libpcre2-dev zlib1g-dev libssl-dev \
      git curl ca-certificates gnupg patch xz-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY patches/ /patches/
COPY docker/scripts/apply-patches.sh /usr/local/bin/apply-patches

# ── Stage 2: libcoraza ─────────────────────────────────────────────────────
FROM build-base AS libcoraza
ARG LIBCORAZA_REF
RUN git clone --depth 1 --branch "${LIBCORAZA_REF}" https://github.com/corazawaf/libcoraza \
 && cd libcoraza && apply-patches libcoraza . \
 && ./build.sh && ./configure --prefix=/usr/local \
 && make -j"$(nproc)" && make install DESTDIR=/out

# ── Stage 3: nginx inkl. Coraza (statisch) ─────────────────────────────────
FROM build-base AS nginx
ARG NGINX_VERSION
ARG NGINX_SHA256
ARG CORAZA_NGINX_REF
COPY docker/keys/nginx/ /keys/
COPY --from=libcoraza /out/ /
RUN git clone --depth 1 --branch "${CORAZA_NGINX_REF}" https://github.com/corazawaf/coraza-nginx \
 && cd coraza-nginx && apply-patches coraza-nginx .
RUN curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
 && curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz.asc" \
 && echo "${NGINX_SHA256}  nginx-${NGINX_VERSION}.tar.gz" | sha256sum -c - \
 && export GNUPGHOME="$(mktemp -d)" \
 && gpg --batch --import /keys/*.key \
 && gpg --batch --verify "nginx-${NGINX_VERSION}.tar.gz.asc" "nginx-${NGINX_VERSION}.tar.gz" \
 && tar xzf "nginx-${NGINX_VERSION}.tar.gz"
# configure-nginx.sh enthält die Optionen aus Abschnitt 4.3
COPY docker/scripts/configure-nginx.sh /src/configure-nginx.sh
WORKDIR /src/nginx-${NGINX_VERSION}
RUN apply-patches "nginx/${NGINX_VERSION}" . \
 && /src/configure-nginx.sh \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out \
 && rm -rf /out/etc/nginx/*.default /out/etc/nginx/html

# ── Stage 4: OWASP CRS ─────────────────────────────────────────────────────
FROM build-base AS crs
ARG CRS_REF
RUN git clone --depth 1 --branch "${CRS_REF}" https://github.com/coreruleset/coreruleset /out/crs \
 && rm -rf /out/crs/.git /out/crs/tests /out/crs/.github

# ── Stage 5: s6-overlay (entpackt, damit die Runtime kein xz braucht) ───────
FROM build-base AS s6
ARG S6_OVERLAY_VERSION
ARG S6_OVERLAY_SHA256_NOARCH
ARG S6_OVERLAY_SHA256_X86_64
ARG S6_OVERLAY_SHA256_AARCH64
ARG TARGETARCH
RUN set -eux; mkdir /out; \
    case "${TARGETARCH}" in \
      amd64) A=x86_64;  S="${S6_OVERLAY_SHA256_X86_64}" ;; \
      arm64) A=aarch64; S="${S6_OVERLAY_SHA256_AARCH64}" ;; \
    esac; \
    base="https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}"; \
    curl -fsSLo noarch.tar.xz "${base}/s6-overlay-noarch.tar.xz"; \
    curl -fsSLo arch.tar.xz   "${base}/s6-overlay-${A}.tar.xz"; \
    echo "${S6_OVERLAY_SHA256_NOARCH}  noarch.tar.xz" | sha256sum -c -; \
    echo "${S}  arch.tar.xz" | sha256sum -c -; \
    tar -C /out -Jxpf noarch.tar.xz; tar -C /out -Jxpf arch.tar.xz

# ── Stage 6: nrp (statisch, ohne cgo) ──────────────────────────────────────
FROM ${GO_IMAGE} AS nrp
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/nrp ./cmd/nrp

# ── Stage 7: Runtime ───────────────────────────────────────────────────────
FROM ${DEBIAN_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcre2-8-0 zlib1g libssl3t64 ca-certificates \
      wireguard-tools iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system nginx \
 && useradd --system --gid nginx --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin nginx \
 && mkdir -p /var/cache/nginx /var/log/nrp/nginx /var/log/nrp/coraza
COPY --from=s6        /out/ /
COPY --from=libcoraza /out/usr/local/lib/ /usr/local/lib/
COPY --from=nginx     /out/ /
COPY --from=crs       /out/crs /usr/share/nrp/coreruleset
COPY --from=nrp       /out/nrp /usr/local/bin/nrp
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/s6/        /etc/s6-overlay/s6-rc.d/
COPY docker/smoke/     /usr/share/nrp/smoke/
RUN ldconfig \
 && nginx -V 2>&1 | grep -q coraza \
 && nginx -t -c /usr/share/nrp/smoke/nginx.conf
EXPOSE 80 443 8443 51820/udp
HEALTHCHECK --interval=30s --timeout=5s CMD ["nrp", "health"]
ENTRYPOINT ["/init"]
```

Hinweise:

- `wireguard-tools` und `iproute2` dienen nur dem Notfall-Debugging. `nrpd` steuert WireGuard direkt über Netlink.
- Der Smoke-Test im letzten `RUN` lädt eine Config mit `coraza on;` und CRS. Passen nginx, libcoraza oder CRS nicht zusammen, scheitert der Build und nicht die Produktion.
- Der Paketname `libssl3t64` ist der trixie-Name (64-bit-time_t-Umstellung). Bei einem späteren Debian-Release prüfen.

### 4.5 Patch-Verzeichnis

Für Sicherheitspatches, die vor einem offiziellen Release eingespielt werden müssen:

```
patches/
├── nginx/
│   └── 1.30.5/
│       └── 0001-CVE-2026-XXXXX.patch      # Patch aus dem nginx-Advisory
├── libcoraza/
│   └── 0001-fix-xyz.patch
└── coraza-nginx/
    └── 0001-fix-xyz.patch
```

Regeln für `apply-patches`:

- nginx-Patches aus Advisories werden mit `patch -p0` angewendet (so veröffentlicht nginx.org sie), Patches für libcoraza/coraza-nginx im Git-Format mit `git apply`.
- **nginx-Patches liegen unter der Version**, für die sie gelten. Wird `NGINX_VERSION` erhöht, greifen alte Patches automatisch nicht mehr.
- **Ein Patch, der sich nicht anwenden lässt, bricht den Build ab.** Das passiert typischerweise, wenn das neue Release den Fix bereits enthält – der Patch wird dann entfernt.
- Jede Patch-Datei beginnt mit einem Kopf: CVE-ID, Quelle (Advisory-URL), Datum, Verantwortlicher, und wann sie entfernt werden kann.
- Gepatchte Builds erhalten ein Suffix in der Image-Version (z. B. `v3.1.0-p1`), sichtbar in `nrp status`.

### 4.6 Statisches nginx.conf im Image

```nginx
user nginx;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nrp/nginx/error.log warn;

events { worker_connections 4096; }

http {
    include       /etc/nginx/mime.types;
    access_log    /var/log/nrp/nginx/access.log combined;
    server_tokens off;

    map $http_upgrade $connection_upgrade { default upgrade; '' close; }

    # Alles Dynamische kommt aus der aktuellen Generation (Symlink)
    include /run/nrp/render/current/http.d/*.conf;
}
```

Kein `load_module` mehr: Coraza ist statisch einkompiliert.

### 4.7 Build- und Update-Pipeline

Die Reaktionszeit auf CVEs hängt weniger von der Distribution ab als von der Pipeline. Ziel: **Patch verfügbar → signiertes Image in der Registry in unter 2 Stunden, ohne manuelle Build-Schritte.**

**Auslöser für Builds (GitHub Actions):**

| Auslöser | Zweck |
|---|---|
| Push/PR | Normaler Entwicklungs-Build mit Tests |
| **Nächtlich (Cron)** | Neubau mit aktuellem Debian-Digest, auch ohne Code-Änderung. OS-Patches fließen so spätestens nach 24 h ein. |
| Renovate-PR | Neue Version von nginx, Go, libcoraza, coraza-nginx, CRS, s6, Basis-Digest |
| `workflow_dispatch` | Notfall-Build nach Einspielen eines Patches |

**Schritte pro Build:**

1. Multi-Arch-Build (`linux/amd64`, `linux/arm64`) mit `docker buildx`, Build-Cache in der Registry.
2. Smoke-Test im Dockerfile (siehe 4.4), danach E2E-Tests gegen das fertige Image (WAF blockiert Test-Payload, `nginx -t` mit gerenderten Golden-File-Configs, API-Auth).
3. `govulncheck` für den nrp-Code und Scan des Images mit Trivy oder Grype. **Abbruch bei CRITICAL/HIGH mit verfügbarem Fix**, Bericht für alles andere.
4. SBOM mit `syft`, als Attestation an das Image gehängt.
5. Signatur mit `cosign` (keyless über GitHub OIDC).
6. Push mit unveränderlichem Tag (`v3.1.0-20261118`) plus beweglichem Tag (`v3.1`). Deployments pinnen auf Digest oder unveränderlichen Tag.

**Renovate (`renovate.json`):**

- Regex-Manager für `versions.env`.
- nginx: Datenquelle GitHub-Tags `nginx/nginx` (`release-1.x.y`), **nur Stable-Linie** (gerade Minor-Version) erlaubt.
- libcoraza, coraza-nginx, coreruleset, s6-overlay: GitHub-Releases.
- `debian` und `golang`: Docker-Digest-Pinning.
- **Automerge** für Patch-Versionen und Digest-Updates bei grüner Pipeline; Minor-Updates (z. B. neue CRS-Version, nginx-Stable-Linie) als PR mit Review, da CRS-Updates neue False Positives bringen können.
- `vulnerabilityAlerts` mit höchster Priorität, unabhängig vom Zeitplan.

**Advisory-Quellen, die überwacht werden:**

- nginx: Mailingliste `nginx-announce` und Security-Advisories von `nginx/nginx` auf GitHub
- Debian: `debian-security-announce` (DSA/DLA) für trixie
- Coraza/libcoraza/coraza-nginx und CRS: GitHub Security Advisories (Repository-Watch auf „Security alerts“)
- Go: `golang-announce`

**Ausrollen auf die Hosts:**

Standard ist bewusstes Aktualisieren über das Image-Tag in `.env` und `docker compose pull && docker compose up -d`. Für automatische Updates optional ein Timer, der nur unveränderliche Tags desselben Minor-Zweigs übernimmt und vorher `nrp doctor` im neuen Image ausführt. Kein Watchtower auf `latest`.

**Runbook für kritische CVEs:**

| Betroffen | Vorgehen |
|---|---|
| nginx, Fix-Release verfügbar | Renovate-PR (oder manuell `NGINX_VERSION` erhöhen) → Pipeline → Release → Rollout |
| nginx, nur Patch verfügbar | Patch nach `patches/nginx/<version>/` → `workflow_dispatch` → Release mit `-pN` → Rollout |
| OpenSSL/glibc/zlib/PCRE2 | Warten auf DSA, dann `workflow_dispatch` (nicht auf den nächtlichen Lauf warten) → Rollout |
| Go-Standardbibliothek | Go-Version in `versions.env` erhöhen → Release (betrifft `nrp` und `libcoraza.so`) |
| Coraza/CRS | Neue Tags pinnen, CRS zuerst mit `DetectionOnly` auf einer Testinstanz prüfen |
| Nicht gebautes nginx-Modul (z. B. mp4, mail) | Mit `nginx -V` bestätigen, dass das Modul fehlt, und als nicht betroffen dokumentieren |

---

## 5. Persistenz: SQLite und Datenlayout

### 5.1 Host-Layout neben `compose.yaml`

```
nrp/
├── compose.yaml
├── .env                      # Image-Tag, öffentliche Endpoints, API-Bind
├── secrets/
│   └── master.key            # 32 Byte, chmod 600, NICHT im data/-Backup
└── data/
    ├── db/                   # Verzeichnis mounten, nicht die Datei!
    │   ├── nrp.db
    │   ├── nrp.db-wal
    │   ├── nrp.db-shm
    │   └── nrp.lock          # flock für Offline-Modus
    ├── backups/              # nrp backup (VACUUM INTO)
    └── logs/
        ├── nginx/            # access.log, error.log
        └── coraza/           # audit.log (JSON)
```

**Alles, was nginx liest (Zertifikate, Configs), wird beim Start aus der DB nach `/run/nrp` (tmpfs) materialisiert.** Das Datenverzeichnis enthält damit nur die DB und Logs. Backup = DB-Datei + `master.key`.

### 5.2 SQLite-Betriebsregeln

- **Verzeichnis mounten, nicht die Datei.** WAL-Modus erzeugt `-wal` und `-shm` im selben Verzeichnis; Einzeldatei-Mounts brechen außerdem bei atomaren Umbenennungen.
- **Nur lokale Dateisysteme.** Kein NFS, kein CIFS. SQLite-Locking ist auf Netzwerkdateisystemen unzuverlässig.
- Pragmas beim Öffnen: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`.
- **Ein Schreib-Connection-Pool mit genau einer Verbindung**, separater Lese-Pool (mehrere Verbindungen). Schreibtransaktionen mit `BEGIN IMMEDIATE`.
- Treiber: `modernc.org/sqlite` (pure Go, `CGO_ENABLED=0`).
- Migrationen: `pressly/goose` mit eingebetteten SQL-Dateien (`embed.FS`), automatisch beim Start von `nrpd`.
- Queries: `sqlc` generiert typsicheren Code aus SQL.
- Backup: `nrp backup` → `VACUUM INTO 'data/backups/nrp-<ts>.db'`. Niemals die laufende DB-Datei per `cp` sichern.

### 5.3 Verschlüsselung von Geheimnissen

Geheimnisse liegen verschlüsselt in der DB (XChaCha20-Poly1305, Schlüssel aus `/run/secrets/nrp_master_key`):

- WireGuard-Hub-Private-Key, Preshared Keys
- ACME-Account-Key
- Private Keys der Zertifikate
- Private Key der internen API-CA

Fehlt der Master-Key, startet `nrpd` nicht (klare Fehlermeldung). Jede verschlüsselte Spalte enthält eine Key-ID, damit `nrp secrets rotate-master-key` später möglich ist.

### 5.4 Schema (Kern)

```sql
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,           -- JSON
  version    INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);
-- z. B. waf.mode, defaults.client_max_body_size, defaults.hsts, acme.directory

CREATE TABLE sites (
  name          TEXT PRIMARY KEY,
  subnet        TEXT NOT NULL UNIQUE,
  connector_ip  TEXT NOT NULL,
  lan_cidr      TEXT,
  public_key    TEXT,
  psk_enc       BLOB,
  os_hint       TEXT,
  email         TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',  -- pending|online|offline
  last_seen_at  TEXT,
  notes         TEXT,
  version       INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE hosts (
  fqdn                 TEXT PRIMARY KEY,
  upstream_scheme      TEXT NOT NULL CHECK (upstream_scheme IN ('http','https')),
  upstream_address     TEXT NOT NULL,
  upstream_port        INTEGER NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
  site_name            TEXT REFERENCES sites(name) ON DELETE RESTRICT,
  external_port        INTEGER NOT NULL DEFAULT 443,
  websockets           INTEGER NOT NULL DEFAULT 0,
  waf                  INTEGER NOT NULL DEFAULT 0,
  client_max_body_size TEXT,                    -- NULL = Default aus settings
  hsts_json            TEXT,                    -- NULL = Default
  acme_email           TEXT,
  status               TEXT NOT NULL DEFAULT 'pending_certificate',
  status_detail        TEXT,
  version              INTEGER NOT NULL DEFAULT 1,
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

CREATE TABLE certificates (
  fqdn         TEXT PRIMARY KEY REFERENCES hosts(fqdn) ON DELETE CASCADE,
  chain_pem    TEXT NOT NULL,
  key_enc      BLOB NOT NULL,
  not_before   TEXT NOT NULL,
  not_after    TEXT NOT NULL,
  ari_renew_at TEXT,                            -- ACME Renewal Information
  issuer       TEXT NOT NULL,
  source       TEXT NOT NULL,                   -- acme|imported
  updated_at   TEXT NOT NULL
);

CREATE TABLE acme_accounts (
  id          INTEGER PRIMARY KEY,
  directory   TEXT NOT NULL,
  email       TEXT,
  key_enc     BLOB NOT NULL,
  reg_json    TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE wg_hub (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  private_key_enc BLOB NOT NULL,
  public_key   TEXT NOT NULL,
  listen_port  INTEGER NOT NULL,
  address      TEXT NOT NULL
);

CREATE TABLE jobs (
  id          TEXT PRIMARY KEY,                 -- ULID
  kind        TEXT NOT NULL,                    -- cert_issue|cert_renew|cert_revoke
  resource    TEXT NOT NULL,
  status      TEXT NOT NULL,                    -- queued|running|succeeded|failed
  attempts    INTEGER NOT NULL DEFAULT 0,
  error       TEXT,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  started_at  TEXT,
  finished_at TEXT
);

CREATE TABLE api_clients (                      -- mTLS-Identitäten
  id            TEXT PRIMARY KEY,               -- ULID
  name          TEXT NOT NULL UNIQUE,
  role          TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
  cert_sha256   TEXT NOT NULL UNIQUE,           -- Fingerprint des Client-Zertifikats
  serial        TEXT NOT NULL,
  not_after     TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);

CREATE TABLE api_tokens (                       -- optional, standardmäßig deaktiviert
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  role        TEXT NOT NULL,
  secret_sha256 BLOB NOT NULL,
  expires_at  TEXT NOT NULL,
  disabled    INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE pki (                              -- interne CA für die API
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  ca_cert_pem   TEXT NOT NULL,
  ca_key_enc    BLOB NOT NULL,
  server_cert_pem TEXT NOT NULL,
  server_key_enc  BLOB NOT NULL
);

CREATE TABLE idempotency_keys (
  key         TEXT PRIMARY KEY,
  actor       TEXT NOT NULL,
  response    BLOB NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE render_generations (
  id          INTEGER PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  status      TEXT NOT NULL,                    -- applied|rejected|rolled_back
  nginx_test_output TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE audit_log (...);                   -- siehe Abschnitt 7
```

---

## 6. Authentifizierung und Autorisierung

### 6.1 Entscheidung: mTLS mit interner CA + rollenbasierte Berechtigungen

**Primäre Methode: mutual TLS (Client-Zertifikate)**, ausgestellt von einer NRP-eigenen CA. Die Rolle eines Clients wird **nicht** aus Zertifikatsfeldern gelesen, sondern über den SHA-256-Fingerprint des Zertifikats in `api_clients` nachgeschlagen.

Begründung gegenüber den Alternativen:

| Methode | Bewertung |
|---|---|
| **Pre-Shared Key / statischer Hash** | Ein gemeinsames Geheimnis für alle, keine Identität pro Client, Rotation betrifft alle Clients gleichzeitig, Audit kann nicht zwischen Clients unterscheiden. Abgelehnt. |
| **Bearer-Token (gehasht gespeichert)** | Gut für Automatisierung, aber ein abgegriffenes Token ist sofort nutzbar (Logs, Shell-History, CI-Variablen). Als optionale Zweitmethode vorgesehen (6.4). |
| **mTLS** | Privater Schlüssel verlässt den Client nie (bei CSR-Ausstellung), Authentifizierung passiert vor jeder HTTP-Verarbeitung, eindeutige Identität pro Client, kurze Laufzeiten, sofortiger Widerruf per DB. **Gewählt.** |
| **OIDC / SSO** | Sinnvoll für eine spätere Web-UI, für Maschinen-Clients und Notfallzugang zu viel Abhängigkeit. Später ergänzbar. |

### 6.2 Ablauf

1. **Erststart:** `nrpd` erzeugt die interne CA (ECDSA P-256) und ein Server-Zertifikat für die API mit den SANs aus `NRP_API_SANS`. CA-Key verschlüsselt in der DB.
2. **Bootstrap des ersten Admins** – nur über den lokalen Socket, also per `docker exec`:
   ```bash
   docker exec -it nrp nrp client issue alice --role admin --out /dev/stdout > alice.bundle.pem
   ```
   Besser mit CSR, damit der private Schlüssel nie im Container existiert:
   ```bash
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout alice.key -subj "/CN=alice" -out alice.csr
   docker exec -i nrp nrp client issue alice --role admin --csr - < alice.csr > alice.crt
   docker exec nrp nrp ca show > nrp-ca.crt
   ```
3. **Nutzung:**
   ```bash
   curl --cacert nrp-ca.crt --cert alice.crt --key alice.key \
        https://proxy.example.com:8443/api/v1/hosts
   ```
4. **Widerruf:** `nrp client revoke alice` → `disabled=1`. Wirkt sofort, da der Fingerprint bei jeder Anfrage geprüft wird. Keine CRL/OCSP nötig.

### 6.3 Regeln

- TLS 1.3 only, `tls.RequireAndVerifyClientCert` gegen die NRP-CA.
- Client-Zertifikate: Laufzeit standardmäßig 90 Tage, `nrp client renew` vor Ablauf.
- Bei jeder Anfrage: Fingerprint → `api_clients` → `disabled = 0` und `not_after > now`, sonst 401.
- **API-Bind standardmäßig nicht öffentlich**: `NRP_API_LISTEN=127.0.0.1:8443` oder die Hub-IP (`10.240.0.1:8443`), damit die API nur lokal bzw. über WireGuard erreichbar ist. Öffentliches Binden erfordert explizites Setzen.
- Rate-Limit für fehlgeschlagene Authentifizierungen pro Quell-IP; fehlgeschlagene Versuche werden auditiert.

### 6.4 Optional: API-Tokens (standardmäßig aus)

Für Systeme, die keine Client-Zertifikate unterstützen. Aktivierung über `NRP_API_TOKENS_ENABLED=true`.

- Format: `nrp_<id>_<secret>`, `secret` = 32 Byte aus `crypto/rand`, base62.
- Gespeichert wird `SHA-256(secret)`. Argon2/bcrypt ist hier nicht nötig: Langsame Hashes schützen schwache Passwörter, ein 256-Bit-Zufallswert ist nicht per Brute Force angreifbar. Vergleich mit `subtle.ConstantTimeCompare`.
- Das Token wird nur bei Erstellung einmal angezeigt.
- Pflicht-Ablaufdatum (max. 365 Tage), Rolle wie bei Clients.
- Auch Token-Anfragen laufen über TLS (Server-Zertifikat), nur der Client-Zertifikatszwang entfällt auf einem separaten Listener `NRP_API_TOKEN_LISTEN`.

### 6.5 Lokaler Zugriff (CLI im Container)

- Unix-Socket `/run/nrp/nrp.sock`, Modus `0600`, Eigentümer root, auf tmpfs (nicht im Bind-Mount, also nicht vom Host aus erreichbar).
- Authentifizierung über `SO_PEERCRED`: UID 0 → Rolle `admin`, Akteur im Audit `local:uid=0`.
- Begründung: Wer `docker exec` ausführen kann, hat ohnehin Root-äquivalenten Zugriff auf den Host. Eine zusätzliche Hürde wäre Schein-Sicherheit und würde den Notfallzugang behindern.

### 6.6 Rollen

| Aktion | viewer | operator | admin |
|---|:-:|:-:|:-:|
| Hosts, Sites, Zertifikate, Status, Jobs lesen | ✓ | ✓ | ✓ |
| Hosts anlegen/ändern/löschen | | ✓ | ✓ |
| Zertifikate erneuern | | ✓ | ✓ |
| Sites anlegen/ändern/löschen, Pubkey setzen, PSK rotieren | | | ✓ |
| Install-Script abrufen (enthält PSK) | | | ✓ |
| WAF-Modus global, Settings | | | ✓ |
| Clients und Tokens verwalten | | | ✓ |
| Audit-Log lesen/verifizieren | | | ✓ |
| Rollback, Reload erzwingen, Backup | | | ✓ |

---

## 7. Audit-Log

### 7.1 Schema

```sql
CREATE TABLE audit_log (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL,                 -- RFC 3339, UTC, ms
  request_id    TEXT NOT NULL,
  actor_type    TEXT NOT NULL,                 -- mtls|token|local|offline|system
  actor_id      TEXT NOT NULL,                 -- Client-Name, Token-ID, uid
  actor_fingerprint TEXT,
  source_ip     TEXT,
  action        TEXT NOT NULL,                 -- host.create, site.delete, waf.set_mode, auth.failed …
  resource_type TEXT NOT NULL,
  resource_id   TEXT,
  before_json   TEXT,                          -- redigiert
  after_json    TEXT,                          -- redigiert
  result        TEXT NOT NULL,                 -- success|denied|failed
  error         TEXT,
  prev_hash     BLOB NOT NULL,
  hash          BLOB NOT NULL                  -- SHA-256(prev_hash || kanonische Zeile)
);
CREATE INDEX audit_ts ON audit_log(ts);
CREATE INDEX audit_resource ON audit_log(resource_type, resource_id);
```

### 7.2 Regeln

- **Atomar mit der Änderung:** Der Audit-Eintrag wird in derselben Transaktion geschrieben wie die Zustandsänderung. Gibt es keinen Audit-Eintrag, gibt es keine Änderung.
- **Auch verweigerte und fehlgeschlagene Aktionen** werden protokolliert (`denied`, `failed`), inklusive fehlgeschlagener Authentifizierung.
- **Systemaktionen** (automatische Zertifikatserneuerung, Site-Statuswechsel) mit `actor_type=system`.
- **Redigierung:** Private Keys, PSKs, Token-Secrets werden vor dem Speichern durch `"[redacted:sha256:abcd…]"` ersetzt (Kurz-Hash erlaubt den Abgleich, ob sich ein Wert geändert hat).
- **Hash-Kette:** Jeder Eintrag enthält den Hash des vorherigen. `nrp audit verify` erkennt nachträgliche Änderungen oder Löschungen in der Mitte. Gegen einen Angreifer mit Root-Zugriff schützt das nur in Verbindung mit externem Export.
- **Export:** Jeder Eintrag wird zusätzlich als JSON-Zeile auf stdout geloggt, damit `docker logs` bzw. ein Log-Shipper eine Kopie außerhalb der DB hat.
- **Keine Lösch-API.** Aufbewahrung über `nrp audit prune --before <datum>` (admin, nur lokal), was selbst als Audit-Eintrag mit dem Hash des letzten gelöschten Eintrags als Anker protokolliert wird.

---

## 8. Parallelität und Reconcile-Loop

### 8.1 Grundprinzip

API-Handler schreiben **nur in die DB**. Sie rendern keine Dateien und signalisieren keine Prozesse. Ein einzelner Reconciler bringt den tatsächlichen Zustand (nginx, WireGuard, Zertifikate auf tmpfs) mit dem DB-Zustand in Einklang.

```
API-Request ──► Validierung ──► DB-Transaktion (Zustand + Audit) ──► Commit
                                                                  │
                                                     notify(reconcile)
                                                                  ▼
                            Reconciler (eine Goroutine, Debounce 300 ms)
                              1. Snapshot aus DB lesen
                              2. Zertifikate nach /run/nrp/certs materialisieren
                              3. Configs in /run/nrp/render/gen-<N>/ rendern
                              4. Hash gleich wie aktuell? → fertig
                              5. nginx -t -c gen-<N>/nginx.test.conf
                              6. OK: Symlink current → gen-<N> (atomar), nginx -s reload
                                 Fehler: Generation 'rejected', Host-Status 'error',
                                         alte Config bleibt aktiv, Audit 'system'
                              7. WireGuard-Peers abgleichen (wgctrl, ReplacePeers)
```

### 8.2 Gleichzeitigkeit

- **Lesen:** beliebig parallel (Lese-Pool, WAL erlaubt Lesen während Schreiben).
- **Schreiben:** serialisiert durch die eine Schreibverbindung. Schreibtransaktionen sind kurz (keine Netzwerkaufrufe innerhalb).
- **Optimistic Locking:** Jede Ressource hat `version`. `GET` liefert `ETag: "<version>"`, `PATCH`/`PUT`/`DELETE` erfordern `If-Match`. Abweichung → `412 Precondition Failed`. Die CLI setzt `If-Match` automatisch aus einem vorherigen `GET`.
- **Idempotenz:** `POST`-Anfragen akzeptieren `Idempotency-Key`. Wiederholungen mit gleichem Schlüssel liefern die gespeicherte Antwort (24 h).
- **Reconciler:** genau eine Instanz, Debounce bündelt viele Änderungen in einen Reload. Reload-Anzahl ist damit unabhängig von der Anzahl paralleler Requests.
- **ACME-Jobs:** Worker-Pool (Standard 4), Lock pro FQDN, Retry mit exponentiellem Backoff. Respektiert die Rate-Limits der CA.
- **Offline-Modus vs. Dienst:** `nrpd` hält dauerhaft einen exklusiven `flock` auf `data/db/nrp.lock`. Der Offline-Modus der CLI versucht denselben Lock und bricht ab, wenn `nrpd` läuft („Dienst läuft – ohne --offline verwenden").

### 8.3 Rollback

Die letzten 10 Generationen bleiben in `/run/nrp/render/` erhalten. `nrp render rollback <gen>` schaltet den Symlink zurück und lädt neu. Da tmpfs flüchtig ist, wird nach einem Container-Neustart immer aus der DB neu gerendert.

---

## 9. REST-API

### 9.1 Konventionen

- Basis: `/api/v1`, JSON, Spezifikation als **OpenAPI 3.1** in `api/openapi.yaml` (Contract-First).
- Server-Stubs und Go-Client mit `oapi-codegen` generiert. Die CLI nutzt denselben generierten Client.
- Fehler nach RFC 9457 (`application/problem+json`).
- Lang laufende Aktionen (Zertifikate) → `202 Accepted` + `Location: /api/v1/jobs/{id}`.
- Paginierung per Cursor (`?limit=&cursor=`).
- Jede Antwort enthält `X-Request-Id`; derselbe Wert steht im Audit-Log.

### 9.2 Ressource Host (Beispiel)

```json
{
  "fqdn": "api.example.com",
  "upstream": {
    "scheme": "http",
    "address": "192.168.1.10",
    "port": 8080,
    "site": null
  },
  "external_port": 443,
  "websockets": true,
  "waf": true,
  "client_max_body_size": "100M",
  "hsts": { "max_age": 31536000, "include_subdomains": true, "preload": false },
  "acme_email": null,
  "status": "active",
  "status_detail": null,
  "certificate": { "not_after": "2027-02-14T09:12:00Z", "issuer": "Let's Encrypt" },
  "version": 3,
  "created_at": "2026-11-18T10:00:00Z",
  "updated_at": "2026-11-18T10:05:00Z"
}
```

Host-Status: `pending_certificate` → `active`, oder `error` (mit `status_detail`, z. B. ACME-Fehler oder abgelehntes `nginx -t`).

### 9.3 Endpunkte

| Methode | Pfad | Rolle | Beschreibung |
|---|---|---|---|
| GET | `/hosts` | viewer | Liste |
| POST | `/hosts` | operator | Anlegen; startet Zertifikatsjob, `201` + Job-Link |
| GET | `/hosts/{fqdn}` | viewer | Detail inkl. ETag |
| PATCH | `/hosts/{fqdn}` | operator | Teiländerung (JSON Merge Patch), `If-Match` |
| PUT | `/hosts/{fqdn}` | operator | Ersetzen (entspricht `--overwrite`), `If-Match` |
| DELETE | `/hosts/{fqdn}?keep_cert=false&revoke=false` | operator | Löschen |
| GET | `/certificates` | viewer | Alle Zertifikate mit Ablauf |
| GET | `/certificates/{fqdn}` | viewer | Detail (ohne Private Key) |
| POST | `/certificates/{fqdn}/renew` | operator | Erneuerung erzwingen → `202` |
| DELETE | `/certificates/{fqdn}?revoke=true` | admin | Zertifikat entfernen/widerrufen |
| GET | `/sites` | viewer | Liste |
| POST | `/sites` | admin | Anlegen (Subnetz-Vergabe) |
| GET | `/sites/{name}?live=true` | viewer | Detail, optional mit Handshake-Status |
| PATCH | `/sites/{name}` | admin | z. B. `lan_cidr`, `notes` |
| DELETE | `/sites/{name}?keep_config=false` | admin | Löschen (409, wenn Hosts die Site nutzen) |
| GET | `/sites/{name}/install-script?os=debian` | admin | `text/x-shellscript` |
| PUT | `/sites/{name}/public-key` | admin | Pubkey setzen |
| POST | `/sites/{name}/rotate-psk` | admin | Neuen PSK erzeugen |
| GET | `/waf` | viewer | Modus, CRS-Version, Hosts mit WAF |
| PUT | `/waf` | admin | `{"mode": "On" \| "DetectionOnly" \| "Off"}` |
| GET | `/settings` | viewer | Defaults |
| PATCH | `/settings` | admin | Defaults ändern |
| GET | `/status` | viewer | nginx, Generation, Zertifikate, WireGuard, Jobs |
| GET | `/render/current` | admin | Gerenderte Config (Debug) |
| GET | `/render/generations` | admin | Historie |
| POST | `/render/rollback` | admin | `{"generation": 41}` |
| POST | `/render/reconcile` | admin | Reconcile erzwingen |
| GET | `/jobs`, `/jobs/{id}` | viewer | Job-Status |
| GET | `/audit?since=&actor=&resource=` | admin | Audit-Log |
| GET | `/audit/verify` | admin | Hash-Kette prüfen |
| GET/POST/DELETE | `/clients[/{name}]` | admin | mTLS-Clients (POST mit CSR) |
| GET/POST/DELETE | `/tokens[/{id}]` | admin | API-Tokens (falls aktiviert) |

---

## 10. CLI und CLI→API-Übersetzung

### 10.1 Ein Binary, drei Modi

`nrp` ist zugleich Dienst und Client:

| Modus | Aufruf | Verbindung |
|---|---|---|
| Dienst | `nrp serve` | (wird von s6 gestartet) |
| Lokal (Standard im Container) | `docker exec -it nrp nrp host list` | Unix-Socket |
| Remote | `nrp --server https://proxy:8443 --cert … --key … --ca … host list` | mTLS-API |
| Offline (Notfall) | `docker exec -it nrp nrp --offline host list` | Direkt auf SQLite, mit `flock` |

Der Remote-Modus **ersetzt `nrp remote-setup` und den SSH-Zugang mit sudo**. Profile in `~/.config/nrp/config.yaml` vermeiden lange Aufrufe.

Komfort auf dem Host:

```bash
alias nrp='docker exec -it nrp nrp'
```

Interaktive Abfragen (bisher `nrp add` ohne Argumente bzw. `-f`) bleiben erhalten, wenn ein TTY vorhanden ist (`-it`). Ohne TTY sind fehlende Pflichtparameter ein Fehler.

### 10.2 Offline-Modus

Für den Fall, dass `nrpd` nicht startet (defekte Migration, fehlerhafter Code):

- Liest und schreibt die DB direkt, schreibt Audit-Einträge mit `actor_type=offline`.
- Kann rendern und nginx neu laden: `nrp --offline render apply`.
- Verweigert den Betrieb, wenn `nrpd` den Lock hält.
- Läuft `nrpd` gar nicht mehr und der Container wurde beendet: `docker compose run --rm --entrypoint nrp nrp --offline …`.

### 10.3 Übersetzungstabelle

| v2 (Python) | v3 CLI | v3 API | Anmerkung |
|---|---|---|---|
| `sudo nrp setup` | – | – | Entfällt: Ist jetzt das Image. Erststart initialisiert DB, CA, WireGuard-Hub. |
| `nrp setup --with-wireguard` | – | – | `NRP_WIREGUARD_ENABLED=true` + `NET_ADMIN` in Compose |
| `nrp setup --with-waf` | – | – | Modul und CRS sind immer im Image; Modus per `nrp waf set` |
| `nrp add FQDN -i IP -p PORT …` | `nrp host add FQDN -i IP -p PORT …` | `POST /hosts` | Gleiche Flags; zusätzlich `--wait` (wartet auf Zertifikat) |
| `nrp add` (interaktiv) | `nrp host add` | `POST /hosts` | Prompts nur mit TTY |
| `nrp add -f` | `nrp host add -f` | `POST /hosts` | |
| `nrp add … --overwrite` | `nrp host add … --overwrite` | `PUT /hosts/{fqdn}` | |
| – | `nrp host set FQDN --waf --no-websockets …` | `PATCH /hosts/{fqdn}` | Neu: Änderung ohne Neuanlage |
| `nrp add … --site home` | `nrp host add … --site home` | `POST /hosts` mit `upstream.site` | Subnetzprüfung serverseitig |
| `nrp remove FQDN` | `nrp host remove FQDN` | `DELETE /hosts/{fqdn}` | |
| `nrp remove FQDN --keep-cert` | `nrp host remove FQDN --keep-cert` | `DELETE /hosts/{fqdn}?keep_cert=true` | |
| `nrp list` | `nrp host list` (Alias `nrp list`) | `GET /hosts` | `-o json\|yaml\|table` |
| `nrp status [-d]` | `nrp status [-d]` | `GET /status` | |
| `nrp site create NAME …` | `nrp site create NAME …` | `POST /sites` | Gleiche Flags |
| `nrp site list` | `nrp site list` | `GET /sites` | |
| `nrp site show NAME --live` | `nrp site show NAME --live` | `GET /sites/{name}?live=true` | Live über WireGuard-Handshake statt Ping |
| `nrp site delete NAME [--keep-config] [-y]` | gleich | `DELETE /sites/{name}?keep_config=…` | |
| `nrp site install-script NAME --os X` | gleich | `GET /sites/{name}/install-script?os=X` | Endpoint aus `NRP_PUBLIC_ENDPOINT` statt IP-Ermittlung |
| `nrp site set-pubkey NAME KEY` | gleich | `PUT /sites/{name}/public-key` | |
| – | `nrp site rotate-psk NAME` | `POST /sites/{name}/rotate-psk` | Neu |
| `nrp waf enable` | `nrp waf set on` | `PUT /waf {"mode":"On"}` | Kein Build mehr |
| `nrp waf enable --detection-only` | `nrp waf set detection-only` | `PUT /waf {"mode":"DetectionOnly"}` | |
| `nrp waf enable --crs-version X` | – | – | CRS-Version ist Build-Argument des Images |
| `nrp waf enable --rebuild` | – | – | Entfällt: Modul und nginx sind immer gemeinsam versioniert |
| `nrp waf disable` | `nrp waf set off` | `PUT /waf {"mode":"Off"}` | |
| `nrp waf status` | `nrp waf status` | `GET /waf` | |
| `nrp f2b enable/disable/status` | – | – | Entfällt, siehe [11.5](#115-fail2ban--crowdsec) |
| `nrp remote-setup` | `nrp client issue/list/revoke/renew` | `/clients` | Ersetzt durch mTLS |
| `nrp completion` | `nrp completion bash\|zsh\|fish` | – | cobra eingebaut |
| – | `nrp cert list/show/renew/remove` | `/certificates` | Neu |
| – | `nrp job list/show/wait` | `/jobs` | Neu |
| – | `nrp audit list/verify/prune` | `/audit` | Neu (prune nur lokal) |
| – | `nrp render show/generations/rollback/apply` | `/render/*` | Neu |
| – | `nrp settings show/set` | `/settings` | Ersetzt Anpassungen in `config.py` |
| – | `nrp token create/list/revoke` | `/tokens` | Neu, optional |
| – | `nrp ca show` | – | CA-Zertifikat für Clients |
| – | `nrp backup [--out]` | – | Nur lokal |
| – | `nrp export` / `nrp apply -f hosts.yaml` | (mehrere Aufrufe) | Deklarativer Import/Export, GitOps-fähig |
| – | `nrp import v2 …` | – | Migration, siehe Abschnitt 14 |
| – | `nrp health` | – | Für den Docker-Healthcheck |
| – | `nrp doctor` | – | Prüft DB, Master-Key, nginx, Modul, wg0, Ports |

### 10.4 Ersatz für `config.py`

| v2 (`config.py`) | v3 |
|---|---|
| `NGINX_CONF_DIR`, `NGINX_SSL_DIR`, `LETSENCRYPT_*` | Fest im Image, nicht mehr konfigurierbar |
| `DEFAULT_CLIENT_MAX_BODY_SIZE`, `DEFAULT_HSTS_MAX_AGE` | `nrp settings set …` (DB) |
| `DEFAULT_REMOTE_USER`, `DEFAULT_SCRIPT_PATH` | Entfällt |
| `WG_OVERLAY_CIDR` | `NRP_WG_OVERLAY_CIDR` (nur bei Erststart, danach in DB) |
| `WG_PORT` | `NRP_WG_PORT` (Standard 51820; v2 hat hier inkonsistent 51825 in `config.py` vs. 51820 in der Doku) |
| `WG_INTERFACE_NAME` | Fest `wg0` |
| `F2B_*` | Entfällt |
| `WAF_*` | Fest im Image; `WAF_CRS_VERSION` → Build-Argument |
| – | `NRP_API_LISTEN`, `NRP_API_SANS`, `NRP_PUBLIC_ENDPOINT`, `NRP_ACME_DIRECTORY`, `NRP_ACME_EMAIL`, `NRP_API_TOKENS_ENABLED`, `NRP_LOG_LEVEL` |

---

## 11. Komponenten im Detail

### 11.1 nginx-Rendering

- Templates als Go `text/template`, eingebettet per `embed.FS`, **keine Template-Dateien im Volume**.
- Pro Generation:
  ```
  /run/nrp/render/gen-<N>/
  ├── http.d/
  │   ├── 00-acme-and-catchall.conf
  │   ├── 10-ssl-params.conf
  │   └── host-<fqdn>.conf
  ├── coraza/
  │   ├── coraza.conf         (SecRuleEngine aus settings.waf.mode)
  │   ├── crs-setup.conf      (aus Image, optional Overrides aus DB)
  │   └── main.conf
  └── nginx.test.conf         (wie /etc/nginx/nginx.conf, aber include auf gen-<N>)
  ```
- Ein Host ohne gültiges Zertifikat wird **nicht** als 443-Server gerendert (nur ACME-Challenge über Port 80). Damit ist kein temporäres `temp_http.conf` mehr nötig.
- Dateinamen werden aus validierten FQDNs gebildet; Validierung erfolgt vor dem Speichern (Port von `validation.py`).
- Golden-File-Tests für jede Template-Variante (siehe Abschnitt 16).

### 11.2 Zertifikate (ACME)

- Bibliothek `go-acme/lego`, Challenge **HTTP-01 über einen globalen Port-80-Server**: `location /.well-known/acme-challenge/` mit Webroot `/run/nrp/acme` für alle Namen.
- Das löst ein Problem von v2: Hosts mit abweichendem externen Port hatten keinen Listener auf Port 80 und waren für Erneuerungen auf das certbot-nginx-Plugin angewiesen.
- Ablage: Kette und verschlüsselter Key in `certificates`, materialisiert nach `/run/nrp/certs/<fqdn>/{fullchain,privkey}.pem` (Modus 0600, Eigentümer root; der nginx-Master liest als root).
- Erneuerung: täglicher Lauf plus Jitter. Bevorzugt nach **ARI** (ACME Renewal Information, von lego unterstützt), Fallback ⅓ der Restlaufzeit. Let's Encrypt verkürzt die Zertifikatslaufzeiten schrittweise, ARI fängt das ohne Codeänderung ab.
- Let's Encrypt verschickt keine Ablauf-E-Mails mehr. `--email` bleibt optional als Account-Kontakt; Überwachung des Ablaufs erfolgt über `GET /status` und Metriken.
- `NRP_ACME_DIRECTORY` erlaubt Staging oder interne ACME-CAs. Tests laufen gegen **Pebble**.
- Bestehende certbot-Zertifikate werden bei der Migration importiert (`source=imported`) und beim nächsten Erneuerungszeitpunkt per ACME ersetzt.

### 11.3 TLS-Parameter

`options-ssl-nginx.conf` und `ssl-dhparams.pem` stammen in v2 von certbot und existieren in v3 nicht mehr. Ersatz: eigenes `10-ssl-params.conf` nach Mozilla-„Intermediate“-Profil (TLS 1.2/1.3, ECDHE-Cipher). `ssl_dhparam` entfällt, da keine DHE-Cipher mehr genutzt werden.

### 11.4 WireGuard

- Steuerung über `wgctrl` (Peers, Keys, Port) und `vishvananda/netlink` (Interface, Adresse, Routen). Keine Shell-Aufrufe von `wg`/`wg-quick`/`ip`, kein `wg0.conf` als Zustand.
- Abgleich ist idempotent: `ConfigureDevice` mit `ReplacePeers=true` aus dem DB-Zustand.
- Hub-Private-Key einmalig erzeugt, verschlüsselt in `wg_hub`.
- Container-Anforderungen: `cap_add: NET_ADMIN`, WireGuard-Kernelmodul auf dem Host (ab Kernel 5.6 enthalten), UDP-Port veröffentlicht.
- `net.ipv4.ip_forward` ist für das reine Proxying **nicht** nötig, da nginx selbst im Namespace von `wg0` die Verbindung zur Site aufbaut. Nur bei Routing zwischen Sites oder LAN-Weiterleitung über den Hub per `sysctls` setzen.
- Site-Status: aus dem letzten Handshake-Zeitpunkt von `wgctrl` (online, wenn < 3 min), statt Ping.
- `NRP_WIREGUARD_ENABLED=false` → kein `NET_ADMIN` nötig, Site-Endpunkte liefern `409`.
- Install-Script: Endpoint aus `NRP_PUBLIC_ENDPOINT` (bisher über Abfrage der öffentlichen IP ermittelt, was im Container unzuverlässig ist).

### 11.5 Fail2Ban → CrowdSec

Fail2Ban arbeitet mit iptables im Netzwerk-Namespace, in dem es läuft. Im Container würden Bans nur den Container-Namespace betreffen und mit `iptables-allports` im schlimmsten Fall die eigene WireGuard- oder API-Erreichbarkeit stören. Deshalb:

- **Empfohlen: CrowdSec** als optionales Compose-Profil (`--profile crowdsec`). Der CrowdSec-Agent liest `data/logs/nginx/*.log` (read-only Mount, Collection `crowdsecurity/nginx`), Sperren setzt der **Firewall-Bouncer auf dem Host** (nftables/iptables).
- Alternative: Fail2Ban bleibt auf dem Host und liest dieselben Logdateien. Die bisherigen Filter (`nginx-404`, `nginx-scanners`) werden als Beispiel unter `contrib/fail2ban/` mitgeliefert.
- `nrp status` zeigt, ob CrowdSec erreichbar ist (optional über `NRP_CROWDSEC_LAPI_URL`).

**Wichtig in beiden Fällen: echte Client-IP.** Bei Docker-Bridge-Netzwerken bleibt die Quell-IP für IPv4 über DNAT erhalten; für IPv6 bzw. mit aktivem `userland-proxy` nicht. Empfehlung: `"userland-proxy": false` in `/etc/docker/daemon.json` und nach Inbetriebnahme im Access-Log verifizieren.

### 11.6 Coraza WAF

- Modul und CRS im Image (Abschnitt 4).
- Globaler Modus (`On`/`DetectionOnly`/`Off`) in `settings`, pro Host `waf=true/false`.
- `crs-setup.conf` aus dem Image als Basis. Eigene Anpassungen (Paranoia Level, `SecRuleRemoveById`) über `nrp waf rules set --file overrides.conf` in der DB, gerendert als `crs-overrides.conf` nach `crs-setup.conf`. In v2 wurde dafür die Datei auf dem Host editiert; das geht im Container verloren.
- Audit-Log nach `data/logs/coraza/audit.log`.
- Pfadänderung: `coraza_rules_file` zeigt auf die aktuelle Generation.

### 11.7 Logs und Rotation

- nginx schreibt in `data/logs/nginx/`. `nrpd` rotiert größenbasiert (Standard 100 MB, 10 Dateien): umbenennen, `nginx -s reopen`.
- `nrpd` selbst loggt strukturiert (`log/slog`, JSON) auf stdout.

### 11.8 Metriken (optional)

`/metrics` (Prometheus) auf `NRP_METRICS_LISTEN`, Standard deaktiviert: Zertifikatsablauf pro Host, Reconcile-Dauer und -Fehler, Jobs, Site-Handshakes, Auth-Fehler.

### 11.9 Container-Härtung

```yaml
read_only: true
security_opt: ["no-new-privileges:true"]
cap_drop: [ALL]
cap_add: [CHOWN, SETUID, SETGID, NET_BIND_SERVICE, NET_ADMIN]   # NET_ADMIN nur mit WireGuard
tmpfs:
  - /run:mode=0755
  - /var/cache/nginx
  - /tmp
```

Die minimale Capability-Liste muss im Test verifiziert werden (nginx-Master und s6 benötigen ggf. `DAC_OVERRIDE` oder `FOWNER`, abhängig von Dateirechten).

---

## 12. Template-Änderungen

Beim Portieren der Jinja-Templates nach `text/template` werden folgende Punkte korrigiert:

| Thema | v2 | v3 |
|---|---|---|
| WebSocket-`Connection`-Header | `proxy_set_header Connection $http_connection;` | `proxy_set_header Connection $connection_upgrade;` mit `map` (siehe 4.6); robust auch bei `keep-alive, Upgrade` |
| `proxy_http_version 1.1` | nur mit WebSockets | immer (Keepalive zum Upstream) |
| HSTS `preload` | immer gesetzt | konfigurierbar, Standard `false`. `preload` ist praktisch nicht rückgängig zu machen und betrifft alle Subdomains. |
| HSTS doppelt (server + location) | nötig wegen `add_header`-Vererbung | bleibt, aber zentral über ein Include |
| IPv6 | Host-Configs nur IPv4 | `listen [::]:…` überall |
| Custom-Port ohne Port 80 | kein ACME-Pfad | globaler Port-80-Server für ACME |
| `ssl_dhparam`, certbot-Optionen | certbot-Dateien | eigenes `10-ssl-params.conf` |
| HTTP/2 | nicht aktiv | `http2 on;` |
| `X-Forwarded-For $remote_addr` | überschreibt | bleibt bewusst so (Edge-Proxy, verhindert Spoofing durch Client-Header) |
| `server_tokens` | Standard (an) | `off` |

---

## 13. Docker Compose

```yaml
name: nrp

services:
  nrp:
    image: ghcr.io/softengine-it/nrp:${NRP_VERSION:?}
    container_name: nrp
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "51820:51820/udp"
      - "127.0.0.1:8443:8443"         # API nur lokal; über WireGuard via Hub-IP
    environment:
      NRP_PUBLIC_ENDPOINT: ${NRP_PUBLIC_ENDPOINT:?}   # z. B. proxy.example.com:51820
      NRP_API_LISTEN: 0.0.0.0:8443
      NRP_API_SANS: proxy.example.com,10.240.0.1,127.0.0.1
      NRP_WIREGUARD_ENABLED: "true"
      NRP_ACME_DIRECTORY: https://acme-v02.api.letsencrypt.org/directory
    secrets:
      - nrp_master_key
    volumes:
      - ./data/db:/var/lib/nrp/db
      - ./data/backups:/var/lib/nrp/backups
      - ./data/logs:/var/log/nrp
    read_only: true
    tmpfs:
      - /run:mode=0755
      - /var/cache/nginx
      - /tmp
    cap_drop: [ALL]
    cap_add: [CHOWN, SETUID, SETGID, NET_BIND_SERVICE, NET_ADMIN]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 30s

  crowdsec:
    profiles: ["crowdsec"]
    image: crowdsecurity/crowdsec:${CROWDSEC_VERSION:?}
    restart: unless-stopped
    environment:
      COLLECTIONS: crowdsecurity/nginx
    volumes:
      - ./data/logs/nginx:/var/log/nginx:ro
      - ./data/crowdsec/config:/etc/crowdsec
      - ./data/crowdsec/data:/var/lib/crowdsec/data
      - ./contrib/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro

secrets:
  nrp_master_key:
    file: ./secrets/master.key
```

Erstinbetriebnahme:

```bash
mkdir -p data/{db,backups,logs} secrets
head -c 32 /dev/urandom > secrets/master.key && chmod 600 secrets/master.key
docker compose up -d
docker exec -it nrp nrp doctor
docker exec -i nrp nrp client issue admin --role admin --csr - < admin.csr > admin.crt
```

---

## 14. Migration von v2

### 14.1 Import-Befehl

Die alten Verzeichnisse werden einmalig read-only eingehängt:

```bash
docker compose run --rm \
  -v /etc/nginx/conf.d:/import/conf.d:ro \
  -v /etc/letsencrypt:/import/letsencrypt:ro \
  -v /var/lib/nrp:/import/nrp:ro \
  -v /etc/wireguard:/import/wireguard:ro \
  --entrypoint nrp nrp --offline import v2 \
    --conf-dir /import/conf.d \
    --letsencrypt /import/letsencrypt \
    --sites /import/nrp/sites.json \
    --wg-conf /import/wireguard/wg0.conf \
    --dry-run
```

Ablauf:

1. `sites.json` → Tabelle `sites` (Felder sind 1:1 vorhanden).
2. `wg0.conf` → Hub-Private-Key und ListenPort nach `wg_hub`. Sites behalten ihre Keys; Clients müssen nichts ändern, wenn Endpoint und Port gleich bleiben.
3. Host-Configs in `conf.d/*.conf` werden geparst (`server_name`, `listen`, `proxy_pass`, aktive `coraza on;`, aktive `Upgrade`-Header, `client_max_body_size`). Hosts, die nicht eindeutig parsebar sind, landen im Bericht und müssen manuell angelegt werden.
4. Zertifikate aus `letsencrypt/live/<fqdn>/` (Symlinks aufgelöst) → `certificates` mit `source=imported`.
5. `--dry-run` zeigt das Ergebnis, ohne zu schreiben. Danach ohne `--dry-run`.

### 14.2 Umschaltung

1. v3 auf dem Zielsystem importieren und mit `nrp render show` prüfen.
2. Host-nginx, Fail2Ban/CrowdSec-Ersatz und `wg-quick@wg0` stoppen (Ports 80/443/51820 werden frei).
3. `docker compose up -d`, `nrp doctor`, Stichproben per `curl`, WireGuard-Handshakes mit `nrp site list`.
4. Rückweg: Container stoppen, Host-Dienste wieder starten. Die alten Dateien wurden nicht verändert.

---

## 15. Projektstruktur Go

```
.
├── cmd/nrp/                 # main.go – ein Binary: serve + CLI
├── api/openapi.yaml         # API-Vertrag
├── internal/
│   ├── apigen/              # oapi-codegen (Server-Interface + Client)
│   ├── server/              # HTTP-Server, Middleware (mTLS, Rollen, Request-ID, Rate-Limit)
│   ├── auth/                # Client-Identitäten, Tokens, Peer-Credentials
│   ├── pki/                 # interne CA, CSR-Signierung
│   ├── store/               # SQLite, Migrationen, sqlc-Code, Transaktionen
│   │   ├── migrations/      # *.sql (goose, embed)
│   │   └── queries/         # *.sql (sqlc)
│   ├── audit/               # Schreiben, Redigieren, Hash-Kette, Verify
│   ├── secrets/             # XChaCha20-Poly1305, Master-Key, Rotation
│   ├── domain/              # Host, Site, Validierung (Port von validation.py)
│   ├── reconcile/           # Reconciler, Generationen, Rollback
│   ├── render/              # Templates (embed) und Rendering
│   │   └── templates/
│   ├── nginx/               # nginx -t, reload, reopen, Log-Rotation
│   ├── acme/                # lego, Jobs, Worker-Pool, ARI
│   ├── wireguard/           # wgctrl, netlink, Subnetz-Vergabe, Install-Script
│   ├── jobs/                # Job-Queue auf SQLite
│   ├── importer/            # v2-Import
│   └── cli/                 # cobra-Befehle, Ausgabeformate, Prompts
├── docker/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── keys/nginx/          # nginx-Signing-Keys (GPG)
│   ├── scripts/             # configure-nginx.sh, apply-patches.sh
│   ├── smoke/               # Smoke-Test-Config für den Build
│   └── s6/                  # s6-rc-Dienste nginx, nrpd
├── patches/                 # Sicherheitspatches vor Upstream-Release (4.5)
├── .github/workflows/       # Build, nächtlicher Rebuild, Notfall-Build
├── renovate.json
├── contrib/
│   ├── crowdsec/
│   └── fail2ban/
├── deploy/compose.yaml
├── versions.env
└── legacy/                  # v1-Bash und v2-Python als Referenz
```

Bibliotheken (Auswahl): `spf13/cobra`, `go-chi/chi`, `oapi-codegen`, `modernc.org/sqlite`, `pressly/goose`, `sqlc`, `go-acme/lego`, `golang.zx2c4.com/wireguard/wgctrl`, `vishvananda/netlink`, `golang.org/x/crypto/chacha20poly1305`, `oklog/ulid`, Standardbibliothek `log/slog`, `text/template`, `embed`.

---

## 16. Tests

| Ebene | Inhalt | Werkzeug |
|---|---|---|
| Unit | Validierung, Subnetz-Vergabe, Redigierung, Hash-Kette, Rollenmatrix | `go test` |
| Golden Files | Jedes Template in allen Varianten (443/Custom-Port, WS an/aus, WAF an/aus, Site) | `go test -update` |
| Store | Migrationen auf/ab, Optimistic Locking, parallele Schreiber | `go test -race` |
| nginx | Gerenderte Configs mit echtem `nginx -t` im Ziel-Image | testcontainers-go |
| ACME | Ausstellung, Erneuerung, Fehlerfälle | Pebble + challtestsrv |
| WireGuard | Interface, Peers, Handshake zwischen zwei Containern | CI-Job mit `NET_ADMIN` |
| WAF | `curl "…?q=<script>"` → 403 bei `On`, 200 + Audit-Eintrag bei `DetectionOnly` | E2E |
| Auth | Ohne Zertifikat, fremde CA, widerrufen, abgelaufen, falsche Rolle | E2E |
| Migration | Import realer v2-Daten (anonymisiert) | Fixture-Verzeichnis |
| Image | Smoke-Test im Build, Trivy/Grype-Scan, `govulncheck`, SBOM (syft), Signatur (cosign) | CI |

---

## 17. Umsetzungsphasen

| Phase | Inhalt | Abnahmekriterium |
|---|---|---|
| 0 | Image aus Quellcode: nginx + libcoraza + coraza-nginx + CRS, Patch-Mechanismus, Pipeline mit nächtlichem Rebuild und Renovate | `nginx -t` mit `coraza on;` im Build grün; WAF blockiert Test-Payload; Testpatch wird angewendet; nächtlicher Build läuft |
| 1 | Go-Grundgerüst, Store, Migrationen, Domain, Rendering, Reconciler, lokale CLI (Socket), Offline-Modus | `nrp host add/list/remove` per `docker exec`, Golden Files grün |
| 2 | ACME mit lego, Jobs, Zertifikate in DB/tmpfs | Ausstellung und Erneuerung gegen Pebble, danach Staging |
| 3 | REST-API, mTLS, PKI, Rollen, Audit mit Hash-Kette | Rollenmatrix-Tests grün; jede Mutation hat Audit-Eintrag |
| 4 | WireGuard (wgctrl/netlink), Sites, Install-Script | Site-Host baut Tunnel auf, Host über Site erreichbar |
| 5 | v2-Import, CrowdSec-Profil, Härtung, Metriken | Import einer realen v2-Installation ohne manuelle Nacharbeit (bis auf gemeldete Ausnahmen) |
| 6 | Doku, Release-Pipeline (Multi-Arch amd64/arm64, SBOM, Signatur) | Release-Tag erzeugt signiertes Image |

---

## 18. Offene Punkte

- **coraza-nginx ist upstream weiterhin experimentell.** Rollout pro Host mit `DetectionOnly` beibehalten. Fallback-Option für später: Coraza in einem separaten Go-Prozess per `auth_request` statt Modul.
- **RHEL-Kompatibilität vorgeschrieben?** Falls ja, Basis auf UBI 10 minimal umstellen (nicht Rocky, siehe 4.1). Build-Schritte bleiben gleich, Paketnamen ändern sich.
- **API-Erreichbarkeit:** nur lokal + WireGuard, oder zusätzlich über eine Management-Netz-IP?
- **Tokens:** Werden sie überhaupt gebraucht (CI/CD, Ticketsysteme), oder reicht mTLS?
- **Audit-Aufbewahrung:** Wie lange? Externer Export (Syslog, Loki) gewünscht?
- **Mehrere Upstreams / Load-Balancing pro Host:** in v2 nicht vorhanden; Schema in v3 so gestalten, dass `upstream` später eine Liste werden kann (eigene Tabelle `host_upstreams`).
- **Web-UI:** später auf Basis der API; Authentifizierung dann über OIDC.
