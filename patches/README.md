# Sicherheitspatches vor Upstream-Release

Patches in diesem Verzeichnis werden beim Image-Build von `docker/scripts/apply-patches.sh`
angewendet (siehe `rewrite.md`, Abschnitt 4.5).

```
patches/
├── nginx/
│   └── <NGINX_VERSION>/          # z. B. 1.30.6 – gilt nur für genau diese Version
│       └── 0001-CVE-2026-XXXXX.patch
├── libcoraza/
│   └── 0001-fix-xyz.patch
└── coraza-nginx/
    └── 0001-fix-xyz.patch
```

## Regeln

- **nginx**: Patches so ablegen, wie nginx.org sie im Advisory veröffentlicht. Sie werden mit
  `patch -p0` im nginx-Quellverzeichnis angewendet. Das Unterverzeichnis muss exakt
  `NGINX_VERSION` aus `versions.env` heißen – wird die Version erhöht, greifen alte Patches
  automatisch nicht mehr (und sollten gelöscht werden).
- **libcoraza / coraza-nginx**: Git-Format (`git diff` / `git format-patch`), angewendet mit `git apply`.
- Reihenfolge: alphabetisch nach Dateiname (`0001-…`, `0002-…`), Endung `.patch`.
- **Ein Patch, der sich nicht anwenden lässt, bricht den Build ab.** Typische Ursache: Das neue
  Release enthält den Fix bereits → Patch entfernen.
- Gepatchte Builds erhalten ein Suffix in der Image-Version (`v3.1.0-p1`), gesetzt über den
  `workflow_dispatch`-Parameter `patch_suffix` des Build-Workflows.

## Pflicht-Kopf

Jede Patch-Datei beginnt mit diesem Kopf (vor dem eigentlichen Diff; `patch` und `git apply`
ignorieren Text vor dem ersten Hunk). Fehlt ein Feld, bricht der Build ab.

```
CVE: CVE-2026-XXXXX
Source: https://nginx.org/en/security_advisories.html (Advisory-/Commit-URL)
Date: 2026-11-18
Owner: <verantwortliche Person oder Team>
Remove-When: nginx >= 1.30.7

--- src/http/ngx_http_core_module.c
+++ src/http/ngx_http_core_module.c
@@ ...
```

Gibt es keine CVE-ID, `CVE: none` eintragen und den Grund in `Source:` verlinken.
