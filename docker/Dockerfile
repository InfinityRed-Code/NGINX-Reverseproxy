# syntax=docker/dockerfile:1.7
#
# NRP v3 – nginx (aus Quellcode) + Coraza WAF + OWASP CRS + nrp (Go) unter s6-overlay.
# Build-Kontext ist das Repo-Root, Versionen kommen aus versions.env:
#
#   docker build $(sed -e '/^#/d' -e '/^$/d' -e 's/^/--build-arg /' versions.env) \
#     -f docker/Dockerfile -t nrp:dev .
#
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
COPY --chmod=0755 docker/scripts/apply-patches.sh /usr/local/bin/apply-patches

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
# configure-nginx.sh enthält die Optionen aus rewrite.md Abschnitt 4.3
COPY --chmod=0755 docker/scripts/configure-nginx.sh /src/configure-nginx.sh
WORKDIR /src/nginx-${NGINX_VERSION}
RUN apply-patches "nginx/${NGINX_VERSION}" . \
 && /src/configure-nginx.sh \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out \
 && rm -rf /out/etc/nginx/*.default /out/etc/nginx/html /out/run /out/var

# ── Stage 4: OWASP CRS ─────────────────────────────────────────────────────
FROM build-base AS crs
ARG CRS_REF
RUN git clone --depth 1 --branch "${CRS_REF}" https://github.com/coreruleset/coreruleset /out/crs \
 && rm -rf /out/crs/.git /out/crs/tests /out/crs/.github /out/crs/docs /out/crs/util \
 && test -f /out/crs/crs-setup.conf.example && test -d /out/crs/rules

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
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
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
FROM ${DEBIAN_IMAGE} AS runtime
ARG VERSION=dev
ARG NGINX_VERSION
ARG LIBCORAZA_REF
ARG CORAZA_NGINX_REF
ARG CRS_REF
LABEL org.opencontainers.image.title="nrp" \
      org.opencontainers.image.description="NGINX Reverse Proxy mit Coraza WAF, REST-API und WireGuard-Sites" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      io.nrp.nginx.version="${NGINX_VERSION}" \
      io.nrp.libcoraza.ref="${LIBCORAZA_REF}" \
      io.nrp.coraza-nginx.ref="${CORAZA_NGINX_REF}" \
      io.nrp.crs.ref="${CRS_REF}"
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
      libpcre2-8-0 zlib1g libssl3t64 ca-certificates \
      wireguard-tools iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system nginx \
 && useradd --system --gid nginx --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin nginx \
 && mkdir -p /var/cache/nginx /var/log/nrp/nginx /var/log/nrp/coraza \
             /var/lib/nrp/db /var/lib/nrp/backups /usr/share/nrp/html
COPY --from=s6        /out/ /
COPY --from=libcoraza /out/usr/local/lib/ /usr/local/lib/
COPY --from=nginx     /out/ /
COPY --from=crs       /out/crs /usr/share/nrp/coreruleset
COPY --from=nrp       /out/nrp /usr/local/bin/nrp
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/html/      /usr/share/nrp/html/
COPY --chmod=0755 docker/s6/s6-rc.d/ /etc/s6-overlay/s6-rc.d/
COPY docker/s6/user-bundles.d/ /etc/s6-overlay/user-bundles.d/
COPY --chmod=0755 docker/s6/scripts/ /etc/s6-overlay/scripts/
COPY docker/smoke/     /usr/share/nrp/smoke/
# Regel-Validierung für den Reconciler (nginx -t prüft Coraza-Regeln nicht)
COPY --chmod=0755 docker/scripts/check-waf.sh /usr/local/bin/nrp-check-waf
# Versionen für `nrp status` / `nrp waf status`
RUN printf 'NRP_VERSION=%s\nNGINX_VERSION=%s\nLIBCORAZA_REF=%s\nCORAZA_NGINX_REF=%s\nCRS_REF=%s\n' \
      "${VERSION}" "${NGINX_VERSION}" "${LIBCORAZA_REF}" "${CORAZA_NGINX_REF}" "${CRS_REF}" \
      > /usr/share/nrp/versions
# Smoke-Test: Modul vorhanden, Config gültig, und ein echter Worker lädt libcoraza + CRS
# und blockiert eine XSS-Payload mit 403. `nginx -t` allein prüft die Regeln NICHT
# (libcoraza wird erst im Worker per dlopen() geladen).
RUN ldconfig \
 && nginx -V 2>&1 | grep -q coraza \
 && nginx -t \
 && sh /usr/share/nrp/smoke/smoke.sh \
 && mkdir -p /tmp/nrp-smoke && chown nginx:nginx /tmp/nrp-smoke \
 && nrp-check-waf /usr/share/nrp/smoke/coraza/main.conf \
 && printf 'SecRuleEngine On\nSecAuditLogRelevantStatus "^(?!404)"\n' > /tmp/bad.conf \
 && ! nrp-check-waf /tmp/bad.conf 2>/dev/null \
 && rm -rf /tmp/bad.conf /tmp/nrp-smoke /var/log/nrp/nginx/* /run/nginx.pid \
 && chown nginx:nginx /var/log/nrp/coraza /var/cache/nginx

# s6-overlay: Root-Dateisystem ist read-only (compose: read_only: true), /run ist tmpfs.
ENV S6_READ_ONLY_ROOT=1 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=30000 \
    S6_VERBOSITY=1
EXPOSE 80 443 8443 51820/udp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["nrp", "health"]
ENTRYPOINT ["/init"]
