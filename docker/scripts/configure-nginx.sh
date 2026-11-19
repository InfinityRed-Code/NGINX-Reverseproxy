#!/bin/sh
# nginx-Build-Konfiguration (rewrite.md 4.3). Wird im nginx-Quellverzeichnis ausgeführt.
# Coraza wird statisch einkompiliert; libcoraza.so wird zur Laufzeit per dlopen() geladen.
set -eu

CORAZA_NGINX_SRC="${CORAZA_NGINX_SRC:-/src/coraza-nginx}"

# -Wno-unused-function: coraza/coraza.h enthält ungenutzte static-Shims (cgo-Präambel),
# nginx baut mit -Werror (siehe coraza-nginx README).
CC_OPT="$(dpkg-buildflags --get CFLAGS) $(dpkg-buildflags --get CPPFLAGS) -Wno-unused-function"
LD_OPT="$(dpkg-buildflags --get LDFLAGS)"

exec ./configure \
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
  --add-module="${CORAZA_NGINX_SRC}" \
  --with-cc-opt="${CC_OPT}" \
  --with-ld-opt="${LD_OPT}"
