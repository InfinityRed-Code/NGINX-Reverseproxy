#!/bin/sh
# apply-patches <komponente> <quellverzeichnis>
#
#   apply-patches nginx/1.30.6 .     -> /patches/nginx/1.30.6/*.patch   (patch -p0, nginx.org-Format)
#   apply-patches libcoraza .        -> /patches/libcoraza/*.patch      (git apply)
#   apply-patches coraza-nginx .     -> /patches/coraza-nginx/*.patch   (git apply)
#
# Regeln (rewrite.md 4.5):
#   - Kein Verzeichnis / keine Patches: nichts zu tun, Erfolg.
#   - Jeder Patch braucht den Kopf (CVE/Source/Date/Owner/Remove-When), siehe patches/README.md.
#   - Ein Patch, der sich nicht sauber anwenden lässt, bricht den Build ab.
set -eu

component="${1:?usage: apply-patches <component> <srcdir>}"
srcdir="${2:?usage: apply-patches <component> <srcdir>}"
dir="${PATCHES_DIR:-/patches}/${component}"

if [ ! -d "$dir" ]; then
  echo "apply-patches: ${component}: kein Patch-Verzeichnis, nichts zu tun"
  exit 0
fi

count=0
for p in "$dir"/*.patch; do
  [ -e "$p" ] || continue
  for field in CVE Source Date Owner Remove-When; do
    if ! grep -q -m1 "^${field}:" "$p"; then
      echo "apply-patches: FEHLER: ${p}: Kopfzeile '${field}:' fehlt (siehe patches/README.md)" >&2
      exit 1
    fi
  done
  echo "apply-patches: ${component}: wende $(basename "$p") an"
  case "$component" in
    nginx/*)
      # Erst trocken prüfen, damit kein halb gepatchter Baum entsteht.
      if ! patch -p0 --dry-run --forward --fuzz=0 -d "$srcdir" < "$p" >/dev/null; then
        echo "apply-patches: FEHLER: ${p} lässt sich nicht anwenden." >&2
        echo "  Enthält das Release den Fix bereits? Dann Patch entfernen." >&2
        exit 1
      fi
      patch -p0 --forward --fuzz=0 -d "$srcdir" < "$p"
      ;;
    *)
      if ! git -C "$srcdir" apply --check "$p"; then
        echo "apply-patches: FEHLER: ${p} lässt sich nicht anwenden." >&2
        echo "  Enthält das Release den Fix bereits? Dann Patch entfernen." >&2
        exit 1
      fi
      git -C "$srcdir" apply "$p"
      ;;
  esac
  count=$((count + 1))
done

echo "apply-patches: ${component}: ${count} Patch(es) angewendet"
