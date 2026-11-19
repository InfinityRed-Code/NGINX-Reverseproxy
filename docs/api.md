# NRP REST-API

Vollständige Referenz aller Endpunkte mit Beispielen. Der maschinenlesbare Vertrag ist
[`api/openapi.yaml`](../api/openapi.yaml); bei Abweichungen gilt die Spezifikation.

- [Grundlagen](#grundlagen): Verbindung, Authentifizierung, Rollen, Fehler, ETag, Idempotenz, Paginierung
- [Hosts](#hosts) · [Zertifikate](#zertifikate) · [Jobs](#jobs)
- [Sites (WireGuard)](#sites-wireguard)
- [WAF](#waf) · [Settings](#settings) · [Status](#status)
- [Render](#render): Konfiguration, Generationen, Rollback
- [Audit](#audit) · [Backup](#backup)
- [Clients (mTLS)](#clients-mtls) · [CA](#ca) · [Tokens](#tokens)
- [Abläufe](#abläufe): typische Aufrufketten
- [Übersicht aller Endpunkte](#übersicht-aller-endpunkte)

---

## Grundlagen

### Verbindung

| | |
|---|---|
| Basis-URL | `https://<host>:8443/api/v1` |
| Transport | TLS 1.3, Client-Zertifikat der NRP-CA erforderlich |
| Format | JSON (`application/json`), Zeitstempel RFC 3339 in UTC |
| Standard-Bind | Nur `127.0.0.1:8443` des Docker-Hosts (siehe `deploy/compose.yaml`) |

Soll die API von außerhalb des Hosts erreichbar sein, die Portfreigabe in `compose.yaml` ändern und den Namen bzw. die IP in
`NRP_API_SANS` aufnehmen; das Server-Zertifikat wird dann beim nächsten Start neu ausgestellt.

### Erster Zugang

Client-Zertifikate stellt nur ein Admin aus. Den ersten Admin legt man lokal im Container an:

```bash
# Schlüssel bleibt beim Client: CSR erzeugen und signieren lassen
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout alice.key -subj "/CN=alice" -out alice.csr
docker exec -i nrp nrp client issue alice --role admin --csr - < alice.csr > alice.crt
docker exec nrp nrp ca show > nrp-ca.crt
```

Alle Beispiele unten verwenden diese Abkürzungen:

```bash
API=https://127.0.0.1:8443/api/v1
alias ncurl='curl -sS --cacert nrp-ca.crt --cert alice.crt --key alice.key'

ncurl $API/status
```

### Authentifizierung

| Weg | Wie | Identität im Audit-Log |
|---|---|---|
| **mTLS** (Standard) | Client-Zertifikat der NRP-CA | `mtls:<client-name>` |
| **Token** (optional) | `Authorization: Bearer nrp_<id>_<secret>` auf dem separaten Token-Listener | `token:<token-id>` |
| **Lokal** | Unix-Socket im Container (`docker exec nrp nrp …`), UID 0 | `local:uid=0`, Rolle `admin` |

- Die Rolle steht nicht im Zertifikat. Bei jeder Anfrage wird der SHA-256-Fingerprint des Zertifikats in der Datenbank
  nachgeschlagen. Ein Zertifikat der NRP-CA, das dort nicht registriert, widerrufen oder abgelaufen ist, erhält `401`.
- Ohne Client-Zertifikat oder mit dem Zertifikat einer fremden CA scheitert bereits der TLS-Handshake; es gibt dann keine HTTP-Antwort.
- Nach 10 fehlgeschlagenen Anmeldungen innerhalb einer Minute erhält die Quell-IP `429` mit `Retry-After: 60`.
  Jeder Fehlversuch steht als `auth.failed` im Audit-Log.

### Rollen

Rollen sind aufsteigend: `viewer` < `operator` < `admin`. Die Mindestrolle steht bei jedem Endpunkt.

| Darf | viewer | operator | admin |
|---|:-:|:-:|:-:|
| Hosts, Sites, Zertifikate, Status, Jobs, WAF, Settings, CA lesen | ✓ | ✓ | ✓ |
| Hosts anlegen/ändern/löschen, Zertifikate erneuern | | ✓ | ✓ |
| Sites verwalten, Install-Script abrufen | | | ✓ |
| WAF-Modus und -Regeln, Settings | | | ✓ |
| Zertifikate entfernen/widerrufen | | | ✓ |
| Clients und Tokens | | | ✓ |
| Audit-Log, Render (Konfiguration, Rollback, Reconcile) | | | ✓ |
| Audit aufräumen, Backup | | | nur lokal |

Fehlt die Rolle, antwortet die API mit `403`; der Versuch steht als `api.denied` im Audit-Log.

```json
{"detail":"Rolle admin erforderlich","request_id":"4231497681e0678b","status":403,"title":"Forbidden","type":"about:blank"}
```

### Fehler

Fehler kommen als `application/problem+json` (RFC 9457):

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "ungueltiger FQDN \"bad\"",
  "request_id": "3d1eb9ccc24fc758"
}
```

| Status | Bedeutung |
|---|---|
| `400` | Ungültige Eingabe (Validierung, unbekanntes Feld, kaputtes JSON) |
| `401` | Nicht authentifiziert (Zertifikat/Token unbekannt, widerrufen oder abgelaufen) |
| `403` | Rolle reicht nicht, oder Operation nur lokal erlaubt |
| `404` | Ressource oder Pfad existiert nicht |
| `409` | Konflikt: existiert bereits, noch in Benutzung, Funktion deaktiviert, Job läuft schon |
| `412` | `If-Match` passt nicht zur aktuellen Version |
| `428` | `If-Match` fehlt |
| `429` | Zu viele fehlgeschlagene Anmeldungen |
| `500` | Interner Fehler; Details stehen im Dienst-Log unter der `request_id` |

Jede Antwort trägt den Header `X-Request-Id`. Derselbe Wert steht im Audit-Log (`request_id`) und im Dienst-Log.

Unbekannte Felder im Request-Body werden mit `400` abgelehnt, damit Tippfehler nicht still ignoriert werden.

### Optimistic Locking (ETag / If-Match)

Hosts und Sites haben eine `version`. `GET` liefert sie als `ETag: "<version>"`; `PATCH`, `PUT` (auf einen bestehenden Host)
und `DELETE` verlangen `If-Match`.

```bash
ncurl -i $API/hosts/app.example.com | grep -i etag
# Etag: "1"

ncurl -X PATCH -H 'Content-Type: application/merge-patch+json' -H 'If-Match: "1"' \
  -d '{"waf":true}' $API/hosts/app.example.com
```

| Situation | Antwort |
|---|---|
| `If-Match` fehlt | `428` – `If-Match fehlt (ETag aus einem vorherigen GET angeben)` |
| Version veraltet | `412` – `Ressource wurde zwischenzeitlich geaendert (aktuelle Version 2)` |
| `If-Match: *` | Passt auf jede bestehende Version (bewusstes Überschreiben) |

### PATCH ist JSON Merge Patch

`PATCH` erwartet `Content-Type: application/merge-patch+json` (RFC 7386): Nur genannte Felder ändern sich, `null` entfernt
einen optionalen Wert, verschachtelte Objekte werden zusammengeführt.

```bash
# nur den Upstream-Port ändern, client_max_body_size auf den Standard zurücksetzen
-d '{"upstream":{"port":9090},"client_max_body_size":null}'
```

### Idempotenz

`POST`-Anfragen akzeptieren `Idempotency-Key` (max. 128 Zeichen). Eine Wiederholung mit gleichem Schlüssel, Pfad und Akteur
liefert 24 Stunden lang die gespeicherte Antwort mit dem zusätzlichen Header `Idempotent-Replayed: true`; es entsteht kein
zweiter Host und kein zweiter Job. Antworten mit Status `5xx` werden nicht gespeichert.

```bash
ncurl -i -X POST -H 'Content-Type: application/json' -H 'Idempotency-Key: 7f3c' \
  -d '{"fqdn":"idem.example.com","upstream":{"scheme":"http","address":"10.0.0.5","port":80}}' $API/hosts
```

### Paginierung

Listen von Hosts, Jobs und Audit-Einträgen nehmen `?limit=` (1–500, Standard 100) und `?cursor=`. Gibt es weitere Einträge,
enthält die Antwort `next_cursor`; diesen Wert unverändert als `cursor` der nächsten Anfrage übergeben. Fehlt `next_cursor`
bzw. ist er `null`, ist die Liste zu Ende.

```bash
ncurl "$API/hosts?limit=1"
# {"items":[{"fqdn":"app.example.com", …}],"next_cursor":"app.example.com"}
ncurl "$API/hosts?limit=1&cursor=app.example.com"
```

### Änderungen wirken asynchron

Schreibende Aufrufe ändern nur die Datenbank und antworten sofort. Ein einzelner Reconciler rendert danach die
nginx-Konfiguration, prüft sie und lädt nginx neu (viele Änderungen werden zu einem Reload gebündelt, typisch unter einer
Sekunde). Ob eine Änderung aktiv ist, zeigen [`GET /status`](#get-status) (`render.generation`, `render.last_error`) und
[`GET /render/generations`](#get-rendergenerations).

---

## Hosts

Ein Host ist ein Reverse-Proxy-Eintrag: öffentlicher Name → Upstream.

### Felder

| Feld | Typ | Beschreibung |
|---|---|---|
| `fqdn` | string | Öffentlicher Name. Wird kleingeschrieben, unveränderlich |
| `upstream.scheme` | `http` \| `https` | Protokoll zum Upstream |
| `upstream.address` | string | IPv4, IPv6 oder Hostname |
| `upstream.port` | 1–65535 | Port des Upstreams |
| `upstream.site` | string \| null | WireGuard-Site, über die der Upstream erreichbar ist. Die Adresse muss dann im Subnetz oder LAN der Site liegen |
| `external_port` | Zahl | Öffentlicher TLS-Port, Standard `443`. `80` und `8443` sind reserviert. Andere Ports zusätzlich in `compose.yaml` veröffentlichen |
| `websockets` | bool | Setzt `Upgrade`/`Connection`-Header, Standard `false` |
| `waf` | bool | Coraza-WAF für diesen Host, Standard `false`. Der Modus ist global, siehe [WAF](#waf) |
| `client_max_body_size` | string \| null | Z. B. `100M`, `2g`. `null` = Wert aus den [Settings](#settings) |
| `hsts` | Objekt \| null | `{max_age, include_subdomains, preload}`. `null` = Wert aus den Settings. `preload` verlangt `max_age` ≥ 31536000 und `include_subdomains` |
| `acme_email` | string \| null | Kontakt, nur informativ |
| `status` | nur lesen | `pending_certificate`, `active` oder `error` |
| `status_detail` | nur lesen | Fehlergrund bei `error` (ACME-Fehler oder Ablehnung durch `nginx -t`) |
| `certificate` | nur lesen | `{not_after, issuer}` oder `null` |
| `version` | nur lesen | Zähler für `If-Match` |

Ein Host mit `pending_certificate` wird noch nicht ausgeliefert; die ACME-Challenge läuft über einen globalen Port-80-Server.
Lehnt `nginx -t` die Konfiguration eines Hosts ab (z. B. nicht auflösbarer Upstream-Hostname), erhält er `error` und wird
ausgelassen, bis er geändert wird. Alle anderen Hosts werden weiter angewendet.

### GET /hosts

Liste aller Hosts, sortiert nach FQDN. Rolle: `viewer`. Parameter: `limit`, `cursor`.

```bash
ncurl "$API/hosts?limit=50"
```

```json
{
  "items": [
    {
      "fqdn": "app.example.com",
      "upstream": {"scheme": "http", "address": "192.168.1.10", "port": 8080, "site": null},
      "external_port": 443,
      "websockets": true,
      "waf": false,
      "client_max_body_size": null,
      "hsts": null,
      "acme_email": null,
      "status": "active",
      "status_detail": null,
      "certificate": {"not_after": "2027-02-17T10:06:33Z", "issuer": "Let's Encrypt"},
      "version": 1,
      "created_at": "2026-11-19T10:06:33.968Z",
      "updated_at": "2026-11-19T10:06:33.968Z"
    }
  ],
  "next_cursor": null
}
```

### POST /hosts

Legt einen Host an und startet die Zertifikatsausstellung. Rolle: `operator`. Header: `Idempotency-Key` (optional).

Pflicht sind `fqdn` und `upstream` (`scheme`, `address`, `port`).

```bash
ncurl -i -X POST -H 'Content-Type: application/json' -d '{
  "fqdn": "app.example.com",
  "upstream": {"scheme": "http", "address": "192.168.1.10", "port": 8080},
  "websockets": true
}' $API/hosts
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Etag: "1"
Location: /api/v1/jobs/01M7SMBCZGM60R0Y8D83WDM51T
X-Request-Id: 6c5485ded01c331a
```

```json
{
  "host": {
    "fqdn": "app.example.com",
    "upstream": {"scheme": "http", "address": "192.168.1.10", "port": 8080, "site": null},
    "external_port": 443, "websockets": true, "waf": false,
    "client_max_body_size": null, "hsts": null, "acme_email": null,
    "status": "pending_certificate", "status_detail": null, "certificate": null,
    "version": 1,
    "created_at": "2026-11-19T10:06:33.968Z", "updated_at": "2026-11-19T10:06:33.968Z"
  },
  "job": {
    "id": "01M7SMBCZGM60R0Y8D83WDM51T", "kind": "cert_issue", "resource": "app.example.com",
    "status": "queued", "attempts": 0, "error": null,
    "created_by": "mtls:alice", "created_at": "2026-11-19T10:06:33.968Z",
    "started_at": null, "finished_at": null
  }
}
```

`Location` zeigt auf den Job, den man mit [`GET /jobs/{id}`](#get-jobsid) verfolgt. Existiert für den Namen bereits ein
gültiges Zertifikat (behalten per `keep_cert` oder importiert), ist der Host sofort `active`; `job` fehlt dann, und
`Location` zeigt auf den Host.

Vollständiges Beispiel mit allen Optionen:

```bash
ncurl -X POST -H 'Content-Type: application/json' -d '{
  "fqdn": "intern.example.com",
  "upstream": {"scheme": "https", "address": "10.240.0.2", "port": 443, "site": "home"},
  "external_port": 8444,
  "websockets": true,
  "waf": true,
  "client_max_body_size": "2g",
  "hsts": {"max_age": 63072000, "include_subdomains": true, "preload": false}
}' $API/hosts
```

| Fehler | Grund |
|---|---|
| `400` | Ungültiger FQDN, Adresse, Port, Schema, Größe oder HSTS; Site unbekannt; Upstream liegt nicht im Netz der Site |
| `409` | Host existiert bereits (zum Ersetzen `PUT`); `upstream.site` gesetzt, aber WireGuard deaktiviert |

### GET /hosts/{fqdn}

Ein Host, mit `ETag`. Rolle: `viewer`.

```bash
ncurl -i $API/hosts/app.example.com
```

```http
HTTP/1.1 200 OK
Etag: "1"
```

Der Body entspricht einem Eintrag aus `GET /hosts`. `404`, wenn der Host nicht existiert.

### PATCH /hosts/{fqdn}

Teiländerung per JSON Merge Patch. Rolle: `operator`. Header: `If-Match` (Pflicht).

```bash
ncurl -X PATCH -H 'Content-Type: application/merge-patch+json' -H 'If-Match: "1"' \
  -d '{"waf": true, "upstream": {"port": 9090}}' $API/hosts/app.example.com
```

Antwort `200` mit dem geänderten Host und neuem `ETag` (`"2"`). Nicht genannte Felder bleiben, hier z. B. `upstream.address`.

```bash
# Werte auf den Standard zurücksetzen
-d '{"client_max_body_size": null, "hsts": null}'
# Upstream nicht mehr über eine Site
-d '{"upstream": {"site": null, "address": "192.168.1.10"}}'
```

`fqdn` lässt sich nicht ändern (`400`). Ein Host im Status `error` wird durch jede Änderung erneut versucht.

### PUT /hosts/{fqdn}

Ersetzt einen Host vollständig oder legt ihn an. Rolle: `operator`.

- Host existiert: `If-Match` ist Pflicht, Antwort `200`. Nicht genannte optionale Felder fallen auf ihren Standard zurück.
- Host existiert nicht: Antwort `201`, die Zertifikatsausstellung startet wie bei `POST` (`Location` zeigt auf den Job).

```bash
ncurl -X PUT -H 'Content-Type: application/json' -H 'If-Match: "2"' -d '{
  "upstream": {"scheme": "https", "address": "192.168.1.20", "port": 443},
  "external_port": 8444,
  "hsts": {"max_age": 63072000, "include_subdomains": true, "preload": false}
}' $API/hosts/app.example.com
```

`fqdn` im Body ist optional, muss aber zum Pfad passen. Status und Zertifikat bleiben beim Ersetzen erhalten.

### DELETE /hosts/{fqdn}

Entfernt einen Host. Rolle: `operator`. Header: `If-Match` (Pflicht). Antwort `204`.

| Parameter | Standard | Wirkung |
|---|---|---|
| `keep_cert` | `false` | Zertifikat in der Datenbank behalten (für späteres Wiederanlegen) |
| `revoke` | `false` | Zertifikat bei der CA widerrufen; läuft als Job `cert_revoke`, danach wird es entfernt |

```bash
ncurl -i -X DELETE -H 'If-Match: "3"' $API/hosts/app.example.com
ncurl -i -X DELETE -H 'If-Match: *' "$API/hosts/app.example.com?keep_cert=true"
ncurl -i -X DELETE -H 'If-Match: *' "$API/hosts/app.example.com?revoke=true"
```

---

## Zertifikate

Zertifikate werden per ACME (HTTP-01) ausgestellt und automatisch erneuert: zum von der CA vorgeschlagenen Zeitpunkt (ARI),
sonst sobald ein Drittel der Laufzeit übrig ist. Private Schlüssel verlassen den Dienst nie über die API.

### GET /certificates

Alle Zertifikate mit Ablauf. Rolle: `viewer`.

```bash
ncurl $API/certificates
```

```json
{
  "items": [
    {
      "fqdn": "app.example.com",
      "not_before": "2026-11-19T09:06:33Z",
      "not_after": "2027-02-17T09:06:33Z",
      "ari_renew_at": "2027-01-18T12:00:00Z",
      "issuer": "Let's Encrypt",
      "source": "acme",
      "updated_at": "2026-11-19T10:06:40.120Z",
      "days_left": 89
    }
  ]
}
```

`source` ist `acme` oder `imported` (aus einer v2-Installation; wird zum Erneuerungszeitpunkt per ACME ersetzt).

### GET /certificates/{fqdn}

Wie oben, zusätzlich mit `chain_pem` (Zertifikatskette, ohne privaten Schlüssel). Rolle: `viewer`.

```bash
ncurl $API/certificates/app.example.com | jq -r .chain_pem | openssl x509 -noout -subject -enddate
```

`404`, solange noch kein Zertifikat ausgestellt ist.

### POST /certificates/{fqdn}/renew

Erzwingt eine Erneuerung. Rolle: `operator`. Header: `Idempotency-Key` (optional).

```bash
ncurl -i -X POST $API/certificates/app.example.com/renew
```

```http
HTTP/1.1 202 Accepted
Location: /api/v1/jobs/01M7SMC0AB12CD34EF56GH78JK
```

Der Body ist der Job (`kind: cert_renew`, `status: queued`). Nach dem Erfolg lädt nginx das neue Zertifikat automatisch.

| Fehler | Grund |
|---|---|
| `404` | Host existiert nicht |
| `409` | Für den Namen läuft bereits ein Zertifikatsjob |

### DELETE /certificates/{fqdn}

Entfernt ein Zertifikat. Rolle: `admin`.

| Aufruf | Antwort | Wirkung |
|---|---|---|
| ohne Parameter | `204` | Zertifikat sofort entfernt. Ein noch vorhandener Host fällt auf `pending_certificate` zurück |
| `?revoke=true` | `202` + Job | Widerruf bei der CA als Job `cert_revoke`, danach Entfernung |

```bash
ncurl -i -X DELETE "$API/certificates/app.example.com?revoke=true"
```

---

## Jobs

Zertifikatsaktionen laufen asynchron. Ein Job durchläuft `queued` → `running` → `succeeded` oder `failed`. Fehlschläge
werden mit wachsendem Abstand bis zu sechsmal versucht; der letzte Fehler steht in `error`.

| `kind` | Auslöser |
|---|---|
| `cert_issue` | Neuer Host ohne Zertifikat |
| `cert_renew` | Automatische oder erzwungene Erneuerung |
| `cert_revoke` | Widerruf beim Löschen |

### GET /jobs

Neueste zuerst. Rolle: `viewer`. Parameter: `limit`, `cursor`, `status` (`queued`, `running`, `succeeded`, `failed`).

```bash
ncurl "$API/jobs?status=failed&limit=20"
```

```json
{
  "items": [
    {
      "id": "01M7SMBCZM8R7QAGSZEKFB5F2W", "kind": "cert_issue", "resource": "idem.example.com",
      "status": "queued", "attempts": 0, "error": null,
      "created_by": "mtls:alice", "created_at": "2026-11-19T10:06:33.972Z",
      "started_at": null, "finished_at": null
    }
  ],
  "next_cursor": "01M7SMBCZM8R7QAGSZEKFB5F2W"
}
```

### GET /jobs/{id}

Ein Job. Rolle: `viewer`.

```bash
# auf den Abschluss warten
while :; do
  s=$(ncurl $API/jobs/01M7SMBCZGM60R0Y8D83WDM51T | jq -r .status)
  [ "$s" = succeeded ] && break
  [ "$s" = failed ] && { echo "fehlgeschlagen"; exit 1; }
  sleep 2
done
```

---

## Sites (WireGuard)

Eine Site ist ein entferntes Netz, das per WireGuard mit dem Hub (`wg0` im Container) verbunden ist. Upstreams hinter der
Site lassen sich dann als Host mit `upstream.site` veröffentlichen.

Ist WireGuard deaktiviert (`NRP_WIREGUARD_ENABLED=false`), antworten **alle** Site-Endpunkte mit `409`.

### Felder

| Feld | Beschreibung |
|---|---|
| `name` | Kleinbuchstaben, Ziffern, `-`; max. 32 Zeichen. Unveränderlich |
| `subnet` | Automatisch vergebenes Subnetz im Overlay (Standard `10.240.0.0/16`) |
| `connector_ip` | Adresse des Site-Hosts im Tunnel (zweite Adresse des Subnetzes) |
| `lan_cidr` | Optional: LAN hinter dem Site-Host; wird in AllowedIPs und Routing aufgenommen |
| `public_key` | WireGuard-Public-Key der Site. Solange er fehlt, gibt es keinen Peer |
| `has_psk` | Ob ein Preshared Key gesetzt ist. Der PSK selbst wird nie ausgegeben, außer im Install-Script |
| `enabled` | `false` = Peer entfernt, Datensatz behalten |
| `status` | `pending` (noch kein Handshake), `online` (Handshake jünger als 3 Minuten), `offline` |
| `last_seen_at` | Zeitpunkt des letzten Handshakes |
| `os_hint`, `email`, `notes` | Metadaten |

### GET /sites

Alle Sites. Rolle: `viewer`.

```bash
ncurl $API/sites
```

```json
{
  "items": [
    {
      "name": "home", "subnet": "10.240.0.0/28", "connector_ip": "10.240.0.2",
      "lan_cidr": "192.168.1.0/24", "public_key": null, "has_psk": true,
      "os_hint": "debian", "email": null, "enabled": true,
      "status": "pending", "last_seen_at": null, "notes": null,
      "version": 1,
      "created_at": "2026-11-19T10:06:33.973Z", "updated_at": "2026-11-19T10:06:33.973Z"
    }
  ]
}
```

### POST /sites

Legt eine Site an, vergibt Subnetz und erzeugt einen PSK. Rolle: `admin`. Header: `Idempotency-Key` (optional).

| Feld | Beschreibung |
|---|---|
| `name` | Pflicht |
| `targets` | Geschätzte Anzahl interner Dienste; bestimmt die Subnetzgröße (/30 bis /24). Standard 6 |
| `subnet_prefix` | Expliziter Präfix 16–30; hat Vorrang vor `targets` |
| `lan_cidr`, `os_hint` (`debian`, `ubuntu`, `alpine`), `email`, `notes` | Optional |

```bash
ncurl -i -X POST -H 'Content-Type: application/json' \
  -d '{"name": "home", "targets": 8, "lan_cidr": "192.168.1.0/24", "os_hint": "debian"}' $API/sites
```

Antwort `201` mit der Site, `ETag: "1"` und `Location: /api/v1/sites/home`.

| Fehler | Grund |
|---|---|
| `400` | Ungültiger Name, `lan_cidr` oder E-Mail |
| `409` | Site existiert bereits; kein freies Subnetz dieser Größe; WireGuard deaktiviert |

### GET /sites/{name}

Eine Site, mit `ETag`. Rolle: `viewer`. Mit `?live=true` zusätzlich der aktuelle Zustand aus dem WireGuard-Interface:

```bash
ncurl "$API/sites/home?live=true"
```

```json
{
  "name": "home", "subnet": "10.240.0.0/28", "connector_ip": "10.240.0.2",
  "status": "online", "last_seen_at": "2026-11-19T10:12:05.000Z",
  "live": {
    "online": true,
    "last_handshake": "2026-11-19T10:12:05Z",
    "endpoint": "203.0.113.7:48194",
    "rx_bytes": 348,
    "tx_bytes": 648
  }
}
```

`live` fehlt, solange die Site keinen Public Key hat.

### PATCH /sites/{name}

Ändert Metadaten per JSON Merge Patch. Rolle: `admin`. Header: `If-Match` (Pflicht).

Änderbar: `lan_cidr`, `notes`, `email`, `os_hint`, `enabled`. `null` oder leerer String löscht den Wert.

```bash
ncurl -X PATCH -H 'Content-Type: application/merge-patch+json' -H 'If-Match: "2"' \
  -d '{"notes": "Keller", "lan_cidr": null}' $API/sites/home

# Site vorübergehend trennen bzw. wieder aktivieren
-d '{"enabled": false}'
```

### DELETE /sites/{name}

Löscht eine Site. Rolle: `admin`. Header: `If-Match` (Pflicht). Antwort `204`.

Mit `?keep_config=true` bleibt der Datensatz erhalten (`enabled: false`, `status: offline`), nur der WireGuard-Peer entfällt.

```bash
ncurl -i -X DELETE -H 'If-Match: *' "$API/sites/home?keep_config=true"
```

`409`, solange Hosts die Site nutzen:

```json
{"detail":"Site home wird noch von 1 Host(s) genutzt","request_id":"178898830e6b4e6d","status":409,"title":"Conflict","type":"about:blank"}
```

### GET /sites/{name}/install-script

Shell-Script, das den Tunnel auf dem Site-Host einrichtet. Rolle: `admin`. Parameter: `os` (`auto`, `debian`, `ubuntu`, `alpine`;
Standard ist der `os_hint` der Site).

**Das Script enthält den Preshared Key.** Jeder Abruf wird im Audit-Log protokolliert (`site.install_script`), die Antwort
trägt `Cache-Control: no-store`.

```bash
ncurl "$API/sites/home/install-script?os=debian" > install-home.sh
scp install-home.sh root@site-host:/tmp/ && ssh root@site-host bash /tmp/install-home.sh
```

Antwort `200` mit `Content-Type: text/x-shellscript`. Das Script installiert WireGuard, erzeugt das Schlüsselpaar auf dem
Site-Host, schreibt `/etc/wireguard/wg-site-<name>.conf`, startet den Tunnel, richtet NAT ein und gibt am Ende den Public Key
aus, der mit [`PUT /sites/{name}/public-key`](#put-sitesnamepublic-key) zu hinterlegen ist.

`409`, wenn `NRP_PUBLIC_ENDPOINT` nicht gesetzt ist.

### PUT /sites/{name}/public-key

Hinterlegt den Public Key der Site; erst danach existiert der Peer auf dem Hub. Rolle: `admin`.

```bash
ncurl -X PUT -H 'Content-Type: application/json' \
  -d '{"public_key": "fGCcEfS0T6eGp0iYvKanEDI8jkM2bH6CJJpOEXcF6W8="}' $API/sites/home/public-key
```

Antwort `200` mit der Site. `400` bei ungültigem Schlüssel, `409`, wenn eine andere Site denselben Schlüssel verwendet.

### POST /sites/{name}/rotate-psk

Erzeugt einen neuen Preshared Key. Rolle: `admin`. Antwort `200` mit der Site.

```bash
ncurl -X POST $API/sites/home/rotate-psk
```

Der Tunnel steht erst wieder, wenn die Site den neuen PSK kennt: Install-Script erneut abrufen und ausrollen. Im Audit-Log
steht nur ein Kurz-Hash des PSK.

---

## WAF

Coraza mit dem OWASP Core Rule Set. Der **Modus** ist global, **ob** ein Host gefiltert wird, bestimmt sein Feld `waf`.

| Modus | Wirkung |
|---|---|
| `On` | Angriffe werden blockiert (`403`) |
| `DetectionOnly` | Nur protokollieren (`data/logs/coraza/audit.log`). Standard |
| `Off` | Regel-Engine aus |

### GET /waf

Rolle: `viewer`.

```bash
ncurl $API/waf
```

```json
{"mode": "DetectionOnly", "crs_version": "v4.30.0", "hosts": ["app.example.com"], "overrides": ""}
```

`hosts` sind die Hosts mit `waf: true`.

### PUT /waf

Setzt Modus und/oder eigene Regeln. Rolle: `admin`. Mindestens eines der Felder angeben; das andere bleibt unverändert.

```bash
ncurl -X PUT -H 'Content-Type: application/json' -d '{"mode": "On"}' $API/waf
```

`overrides` ist eine Datei mit Coraza-Direktiven (max. 256 KiB). Alles vor der Zeile `# nrp:after-rules` wird **vor** den
CRS-Regeln eingebunden (z. B. Paranoia Level), alles danach **nach** ihnen (nötig für `SecRuleRemoveById`).

```bash
jq -n --rawfile o overrides.conf '{overrides: $o}' | \
  ncurl -X PUT -H 'Content-Type: application/json' -d @- $API/waf
```

```text
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=2"
# nrp:after-rules
SecRuleRemoveById 920350
```

Die API speichert die Regeln ungeprüft und antwortet `200`. Geprüft wird beim Anwenden: Kann Coraza die Regeln nicht laden,
wird die Generation abgelehnt, die bisherige Konfiguration bleibt aktiv, und der Fehler steht in `GET /status`
(`render.last_error`) sowie in `GET /render/generations`. Coraza nutzt Go-Regex (RE2): Lookaheads wie `(?!…)` sind nicht erlaubt.

---

## Settings

Globale Standardwerte für Hosts, die selbst keinen Wert setzen.

### GET /settings

Rolle: `viewer`.

```bash
ncurl $API/settings
```

```json
{
  "client_max_body_size": "100M",
  "hsts": {"max_age": 31536000, "include_subdomains": true, "preload": false},
  "acme_email": null
}
```

### PATCH /settings

Rolle: `admin`. JSON Merge Patch; `hsts` darf teilweise angegeben werden.

```bash
ncurl -X PATCH -H 'Content-Type: application/merge-patch+json' \
  -d '{"client_max_body_size": "200M", "hsts": {"max_age": 63072000}, "acme_email": "ops@example.com"}' \
  $API/settings
```

```json
{
  "client_max_body_size": "200M",
  "hsts": {"max_age": 63072000, "include_subdomains": true, "preload": false},
  "acme_email": "ops@example.com"
}
```

`acme_email` ist der Kontakt des ACME-Accounts und wird beim Start des Dienstes gelesen. `400` bei unbekanntem Schlüssel oder
ungültigem Wert.

---

## Status

### GET /status

Gesamtzustand. Rolle: `viewer`.

```bash
ncurl $API/status
```

```json
{
  "version": "v3.0.0",
  "mode": "service",
  "nginx": {"running": true, "version": "1.30.6"},
  "render": {"generation": 12, "pinned": false, "last_error": null},
  "hosts": {"total": 3, "active": 2, "pending_certificate": 1, "error": 0},
  "certificates": {"total": 2, "expiring_30d": 0, "next_expiry": "2027-02-17T09:06:33Z"},
  "wireguard": {
    "enabled": true, "address": "10.240.0.1/16", "listen_port": 51820,
    "public_key": "8UnVPB7PYxhNZvHECw234BlEApQwITUOXPiVkfmEiF0=",
    "sites_total": 1, "sites_online": 1
  },
  "jobs": {"queued": 0, "running": 0, "failed": 0},
  "waf": {"mode": "On", "hosts": 1}
}
```

| Feld | Bedeutung |
|---|---|
| `mode` | `service` (Dienst läuft) oder `offline` (CLI mit `--offline`) |
| `render.generation` | Aktive Konfigurationsgeneration |
| `render.pinned` | `true` nach einem Rollback; automatische Änderungen ruhen bis `POST /render/reconcile` |
| `render.last_error` | Letzter Fehler beim Anwenden (`nginx -t`, Regelcheck, Reload, WireGuard) |
| `crowdsec.reachable` | Nur vorhanden, wenn `NRP_CROWDSEC_LAPI_URL` gesetzt ist |

Für Monitoring gibt es zusätzlich Prometheus-Metriken unter `/metrics`, wenn `NRP_METRICS_LISTEN` gesetzt ist (eigener
Port, ohne Authentifizierung – nicht öffentlich binden).

---

## Render

Der Reconciler schreibt jede Konfiguration als **Generation** und behält die letzten 10 auf dem tmpfs. Alle Endpunkte: Rolle `admin`.

### GET /render/current

Die aktive Generation als Dateien (ohne Zertifikatsschlüssel).

```bash
ncurl $API/render/current | jq -r '.files["http.d/host-app.example.com.conf"]'
```

```json
{
  "generation": 12,
  "files": {
    "http.d/00-acme-and-catchall.conf": "…",
    "http.d/10-ssl-params.conf": "…",
    "http.d/host-app.example.com.conf": "…",
    "snippets/hsts-app.example.com.conf": "…",
    "coraza/coraza.conf": "…",
    "coraza/crs-setup.conf": "…",
    "coraza/crs-overrides.conf": "…",
    "coraza/crs-overrides-after.conf": "…",
    "coraza/main.conf": "…",
    "nginx.test.conf": "…"
  }
}
```

### GET /render/generations

Historie, neueste zuerst.

```bash
ncurl $API/render/generations
```

```json
{
  "items": [
    {
      "id": 12, "status": "applied", "current": true, "available": true,
      "content_sha256": "d0f62195a116def974ea5e66d4829b1963467282b1ee9fafdb43a7ed5af42228",
      "nginx_test_output": null, "created_at": "2026-11-19T10:06:33.992Z"
    },
    {
      "id": 11, "status": "rejected", "current": false, "available": false,
      "content_sha256": "…",
      "nginx_test_output": "nginx: [emerg] host not found in upstream \"backend.invalid\" in …/http.d/host-x.example.com.conf:30",
      "created_at": "2026-11-19T10:05:12.101Z"
    }
  ]
}
```

| `status` | Bedeutung |
|---|---|
| `applied` | Geprüft und aktiviert |
| `rejected` | Von `nginx -t` oder dem Coraza-Regelcheck abgelehnt; `nginx_test_output` nennt den Grund |
| `rolled_back` | War aktiv und wurde durch einen Rollback ersetzt |

`available` gibt an, ob die Dateien noch vorhanden sind, ein Rollback also möglich ist.

### POST /render/rollback

Schaltet auf eine frühere Generation zurück und lädt nginx neu.

```bash
ncurl -X POST -H 'Content-Type: application/json' -d '{"generation": 11}' $API/render/rollback
```

```json
{"generation": 11, "changed": true, "reloaded": true, "error": null}
```

Der Rollback **pinnt** die Generation: Die Datenbank bleibt unverändert, und automatische Änderungen werden nicht mehr
angewendet, bis `POST /render/reconcile` aufgerufen wird. `409`, wenn die Generation nicht mehr vorhanden ist.

### POST /render/reconcile

Rendert sofort aus der Datenbank, prüft, wendet an und hebt einen Rollback-Pin auf.

```bash
ncurl -X POST $API/render/reconcile
```

```json
{"generation": 13, "changed": true, "reloaded": true, "error": null}
```

Ist `error` gesetzt, wurde die neue Generation abgelehnt und `generation` nennt die weiterhin aktive.

---

## Audit

Jede Änderung, jeder verweigerte Zugriff und jede fehlgeschlagene Aktion erzeugt einen Eintrag – in derselben Transaktion
wie die Änderung selbst. Jeder Eintrag enthält den Hash seines Vorgängers. Lesende Zugriffe werden nicht protokolliert.

### GET /audit

Neueste zuerst. Rolle: `admin`.

| Parameter | Beschreibung |
|---|---|
| `since` | Ab Zeitpunkt (RFC 3339) |
| `actor` | Client-Name, Token-ID oder `uid=0` |
| `resource` | Ressourcen-ID (z. B. FQDN, Site-Name) oder Typ (`host`, `site`, `certificate`, `client`, …) |
| `limit`, `cursor` | Paginierung |

```bash
ncurl "$API/audit?resource=app.example.com&since=2026-11-19T00:00:00Z&limit=20"
```

```json
{
  "items": [
    {
      "seq": 9, "ts": "2026-11-19T10:06:33.971Z", "request_id": "aef6a48a28116e31",
      "actor_type": "mtls", "actor_id": "alice",
      "actor_fingerprint": "6709781eeeadf7dff0a1aeb14e70f9848bc9dda10ee91526cfcd2d4589c1b5a5",
      "source_ip": "10.240.0.2",
      "action": "host.replace", "resource_type": "host", "resource_id": "app.example.com",
      "before": {"fqdn": "app.example.com", "external_port": 443, "waf": true, "version": 2},
      "after":  {"fqdn": "app.example.com", "external_port": 8444, "waf": false, "version": 3},
      "result": "success", "error": null,
      "hash": "16a27cc7fbb19144bb32fba8ed8b100eb2b80dce70a22d9d1511e792f4734a5a"
    }
  ],
  "next_cursor": "9"
}
```

`before`/`after` enthalten die vollständige Ressource (oben gekürzt). `actor_type` ist `mtls`, `token`, `local`, `offline`
oder `system` (automatische Aktionen wie Erneuerungen). `result` ist `success`, `denied` oder `failed`. Geheimnisse sind durch
`[redacted:sha256:…]` ersetzt.

Wichtige Aktionen: `host.create/update/replace/delete`, `site.create/update/delete/disable/set_public_key/rotate_psk/install_script`,
`certificate.issue/renew/revoke/delete`, `waf.set`, `settings.update`, `client.issue/renew/revoke/purge`, `token.create/revoke`,
`render.rollback/reconcile/rejected`, `backup.create`, `audit.prune`, `auth.failed`, `api.denied`.

### GET /audit/verify

Prüft die Hash-Kette. Rolle: `admin`.

```bash
ncurl $API/audit/verify
```

```json
{"ok": true, "entries": 24, "first_seq": 1, "last_seq": 24, "broken_at_seq": null, "error": null}
```

Bei `ok: false` nennen `broken_at_seq` und `error` die Stelle, an der ein Eintrag verändert, gelöscht oder eingefügt wurde.

### POST /audit/prune

Löscht Einträge vor einem Zeitpunkt. Rolle: `admin`, **nur lokal** (Socket bzw. `--offline`); über die Netzwerk-API `403`.

```bash
docker exec nrp nrp audit prune --before 90d --yes
```

Body: `{"before": "2026-08-01T00:00:00Z"}`. Antwort:

```json
{"deleted": 1840, "anchor_hash": "9c1f…"}
```

Das Löschen wird selbst protokolliert (`audit.prune`) mit dem Hash des letzten gelöschten Eintrags als Anker; `verify` bleibt
danach gültig.

---

## Backup

### POST /backup

Schreibt eine konsistente Kopie der Datenbank (`VACUUM INTO`) ins Backup-Verzeichnis. Rolle: `admin`, **nur lokal**.

```bash
docker exec nrp nrp backup --out vor-update.db
```

Body (optional): `{"name": "vor-update.db"}`; ohne Namen `nrp-<JJJJMMTT-HHMMSS>.db`. Antwort `201`:

```json
{"path": "/var/lib/nrp/backups/vor-update.db"}
```

Auf dem Host liegt die Datei unter `data/backups/`. Zum Wiederherstellen gehört zusätzlich `secrets/master.key`.
`409`, wenn die Datei bereits existiert.

---

## Clients (mTLS)

Ein Client ist eine API-Identität mit Rolle und genau einem gültigen Zertifikat. Alle Endpunkte: Rolle `admin`.

### GET /clients

```bash
ncurl $API/clients
```

```json
{
  "items": [
    {
      "id": "01M7SMBD1M9EE2R2FEF7X7QGCA", "name": "ci", "role": "operator",
      "cert_sha256": "6709781eeeadf7dff0a1aeb14e70f9848bc9dda10ee91526cfcd2d4589c1b5a5",
      "serial": "2419028ce7ef0c90712b8d293c58a369",
      "not_after": "2026-12-19T10:06:34Z", "disabled": false,
      "created_by": "mtls:alice", "created_at": "2026-11-19T10:06:34.036Z", "last_used_at": null
    }
  ]
}
```

### POST /clients

Stellt ein Client-Zertifikat aus.

| Feld | Beschreibung |
|---|---|
| `name` | Pflicht, eindeutig |
| `role` | Pflicht: `viewer`, `operator` oder `admin` |
| `csr_pem` | CSR als PEM. Empfohlen: der private Schlüssel bleibt beim Client |
| `days` | Laufzeit 1–397, Standard 90 |

Mit CSR (Subject und Erweiterungen des CSR werden ignoriert, es zählt nur der öffentliche Schlüssel):

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ci.key -subj "/CN=ci" -out ci.csr
jq -n --rawfile csr ci.csr '{name: "ci", role: "operator", days: 30, csr_pem: $csr}' | \
  ncurl -X POST -H 'Content-Type: application/json' -d @- $API/clients | jq -r .cert_pem > ci.crt
```

Ohne CSR erzeugt der Server das Schlüsselpaar und liefert `key_pem` **einmalig** in der Antwort:

```bash
ncurl -X POST -H 'Content-Type: application/json' \
  -d '{"name": "ci", "role": "operator", "days": 30}' $API/clients > ci.json
jq -r .cert_pem ci.json > ci.crt; jq -r .key_pem ci.json > ci.key; chmod 600 ci.key
```

Antwort `201` (`Cache-Control: no-store`):

```json
{
  "client": {"id": "01M7SMBD1M9EE2R2FEF7X7QGCA", "name": "ci", "role": "operator", "not_after": "2026-12-19T10:06:34Z", "disabled": false},
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n…",
  "ca_pem": "-----BEGIN CERTIFICATE-----\n…"
}
```

`409`, wenn der Name vergeben ist (auch bei widerrufenen Clients, bis sie mit `purge` entfernt sind).

### GET /clients/{name}

Ein Client, Felder wie in der Liste.

### POST /clients/{name}/renew

Stellt ein neues Zertifikat aus. Das alte wird **sofort** ungültig, weil der gespeicherte Fingerprint ersetzt wird.
Body wie bei `POST /clients`, ohne `name` und `role` (`csr_pem`, `days`; `{}` für Standardwerte). Antwort `200` wie beim Ausstellen.

```bash
jq -n --rawfile csr ci.csr '{csr_pem: $csr}' | \
  ncurl -X POST -H 'Content-Type: application/json' -d @- $API/clients/ci/renew | jq -r .cert_pem > ci.crt
```

`409` bei einem widerrufenen Client.

### DELETE /clients/{name}

Widerruft den Client. Wirkt mit der nächsten Anfrage, ohne CRL. Antwort `204`.

```bash
ncurl -i -X DELETE $API/clients/ci                # widerrufen, Eintrag bleibt (Nachvollziehbarkeit)
ncurl -i -X DELETE "$API/clients/ci?purge=true"   # Eintrag entfernen, Name wird wieder frei
```

---

## CA

### GET /ca

CA-Zertifikat der API (öffentlich, für `--cacert`). Rolle: `viewer`.

```bash
ncurl $API/ca | jq -r .ca_pem > nrp-ca.crt
```

```json
{"ca_pem": "-----BEGIN CERTIFICATE-----\n…"}
```

---

## Tokens

Bearer-Tokens für Systeme ohne Client-Zertifikate. Standardmäßig aus; ohne `NRP_API_TOKENS_ENABLED=true` antworten alle
Token-Endpunkte mit `409`. Benutzt werden Tokens auf einem **eigenen Listener** (`NRP_API_TOKEN_LISTEN`, z. B.
`0.0.0.0:8444`), der TLS ohne Client-Zertifikat spricht. Verwaltet werden sie über die normale mTLS-API. Alle Endpunkte: Rolle `admin`.

### POST /tokens

| Feld | Beschreibung |
|---|---|
| `name` | Pflicht |
| `role` | Pflicht |
| `expires_in_days` | 1–365, Standard 90 |

```bash
ncurl -X POST -H 'Content-Type: application/json' \
  -d '{"name": "ticket", "role": "viewer", "expires_in_days": 30}' $API/tokens
```

```json
{
  "secret": "nrp_01M7SMBD1PYD9N85PDK8ZX1K8V_uqfdrUtUQ0skSte9osucluD85CfoDYF3udpmsd2aImY",
  "token": {
    "id": "01M7SMBD1PYD9N85PDK8ZX1K8V", "name": "ticket", "role": "viewer",
    "expires_at": "2026-12-19T10:06:34.038Z", "disabled": false,
    "created_by": "mtls:alice", "created_at": "2026-11-19T10:06:34.038Z", "last_used_at": null
  }
}
```

`secret` wird **nur hier** angezeigt; gespeichert ist nur sein SHA-256.

Verwendung:

```bash
curl -sS --cacert nrp-ca.crt \
  -H "Authorization: Bearer nrp_01M7SMBD1PYD9N85PDK8ZX1K8V_uqfdr…" \
  https://proxy.example.com:8444/api/v1/hosts
```

### GET /tokens

Liste ohne Secrets, Felder wie `token` oben.

### DELETE /tokens/{id}

Widerruft ein Token. Antwort `204`.

```bash
ncurl -i -X DELETE $API/tokens/01M7SMBD1PYD9N85PDK8ZX1K8V
```

---

## Abläufe

### Host veröffentlichen und auf das Zertifikat warten

```bash
job=$(ncurl -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -d '{
  "fqdn": "app.example.com",
  "upstream": {"scheme": "http", "address": "192.168.1.10", "port": 8080},
  "waf": true
}' $API/hosts | jq -r '.job.id // empty')

while [ -n "$job" ]; do
  read -r status error < <(ncurl $API/jobs/$job | jq -r '[.status, .error // "-"] | @tsv')
  case $status in
    succeeded) break ;;
    failed) echo "Zertifikat fehlgeschlagen: $error" >&2; exit 1 ;;
  esac
  sleep 2
done
ncurl $API/hosts/app.example.com | jq '{status, certificate}'
```

### Host sicher ändern (kein Überschreiben fremder Änderungen)

```bash
etag=$(ncurl -sD - -o /dev/null $API/hosts/app.example.com | tr -d '\r' | awk 'tolower($1)=="etag:" {print $2}')
code=$(ncurl -o /dev/null -w '%{http_code}' -X PATCH \
  -H 'Content-Type: application/merge-patch+json' -H "If-Match: $etag" \
  -d '{"websockets": true}' $API/hosts/app.example.com)
[ "$code" = 412 ] && echo "zwischenzeitlich geändert – neu lesen und wiederholen"
```

### Site einrichten und Dienst dahinter veröffentlichen

```bash
ncurl -X POST -H 'Content-Type: application/json' -d '{"name": "home", "targets": 8}' $API/sites
ncurl "$API/sites/home/install-script" > install-home.sh      # auf dem Site-Host ausführen
ncurl -X PUT -H 'Content-Type: application/json' \
  -d '{"public_key": "<Ausgabe des Scripts>"}' $API/sites/home/public-key
ncurl "$API/sites/home?live=true" | jq .live                   # online: true?

ncurl -X POST -H 'Content-Type: application/json' -d '{
  "fqdn": "nas.example.com",
  "upstream": {"scheme": "https", "address": "10.240.0.2", "port": 5001, "site": "home"}
}' $API/hosts
```

### WAF gefahrlos scharf schalten

```bash
ncurl -X PUT -H 'Content-Type: application/json' -d '{"mode": "DetectionOnly"}' $API/waf
# … data/logs/coraza/audit.log beobachten, Ausnahmen als overrides hinterlegen …
ncurl -X PUT -H 'Content-Type: application/json' -d '{"mode": "On"}' $API/waf
ncurl $API/status | jq .render      # last_error muss null sein
```

### Fehlerhafte Änderung zurücknehmen

```bash
ncurl $API/status | jq .render                                  # last_error ansehen
ncurl $API/render/generations | jq '.items[] | {id, status, current, available}'
ncurl -X POST -H 'Content-Type: application/json' -d '{"generation": 11}' $API/render/rollback
# Ursache in der Datenbank beheben (Host/WAF korrigieren), dann den Pin aufheben:
ncurl -X POST $API/render/reconcile
```

---

## Übersicht aller Endpunkte

| Methode | Pfad | Rolle | Beschreibung |
|---|---|---|---|
| GET | `/hosts` | viewer | Hosts auflisten |
| POST | `/hosts` | operator | Host anlegen, Zertifikat anfordern |
| GET | `/hosts/{fqdn}` | viewer | Host lesen (ETag) |
| PATCH | `/hosts/{fqdn}` | operator | Host teilweise ändern |
| PUT | `/hosts/{fqdn}` | operator | Host ersetzen oder anlegen |
| DELETE | `/hosts/{fqdn}` | operator | Host entfernen (`keep_cert`, `revoke`) |
| GET | `/certificates` | viewer | Zertifikate mit Ablauf |
| GET | `/certificates/{fqdn}` | viewer | Zertifikat mit Kette |
| POST | `/certificates/{fqdn}/renew` | operator | Erneuerung erzwingen |
| DELETE | `/certificates/{fqdn}` | admin | Zertifikat entfernen (`revoke`) |
| GET | `/jobs` | viewer | Jobs auflisten (`status`) |
| GET | `/jobs/{id}` | viewer | Job lesen |
| GET | `/sites` | viewer | Sites auflisten |
| POST | `/sites` | admin | Site anlegen |
| GET | `/sites/{name}` | viewer | Site lesen (`live`) |
| PATCH | `/sites/{name}` | admin | Metadaten ändern, aktivieren/deaktivieren |
| DELETE | `/sites/{name}` | admin | Site löschen (`keep_config`) |
| GET | `/sites/{name}/install-script` | admin | Install-Script (enthält PSK) |
| PUT | `/sites/{name}/public-key` | admin | Public Key hinterlegen |
| POST | `/sites/{name}/rotate-psk` | admin | Neuen PSK erzeugen |
| GET | `/waf` | viewer | Modus, CRS-Version, Hosts, eigene Regeln |
| PUT | `/waf` | admin | Modus und eigene Regeln setzen |
| GET | `/settings` | viewer | Standardwerte lesen |
| PATCH | `/settings` | admin | Standardwerte ändern |
| GET | `/status` | viewer | Gesamtzustand |
| GET | `/render/current` | admin | Aktive Konfiguration |
| GET | `/render/generations` | admin | Historie der Generationen |
| POST | `/render/rollback` | admin | Auf frühere Generation zurückschalten |
| POST | `/render/reconcile` | admin | Sofort anwenden, Pin aufheben |
| GET | `/audit` | admin | Audit-Log lesen |
| GET | `/audit/verify` | admin | Hash-Kette prüfen |
| POST | `/audit/prune` | admin, lokal | Alte Einträge löschen |
| POST | `/backup` | admin, lokal | Datenbank-Backup |
| GET | `/clients` | admin | mTLS-Clients auflisten |
| POST | `/clients` | admin | Client-Zertifikat ausstellen |
| GET | `/clients/{name}` | admin | Client lesen |
| POST | `/clients/{name}/renew` | admin | Client-Zertifikat erneuern |
| DELETE | `/clients/{name}` | admin | Client widerrufen (`purge`) |
| GET | `/ca` | viewer | CA-Zertifikat der API |
| GET | `/tokens` | admin | Tokens auflisten |
| POST | `/tokens` | admin | Token erstellen |
| DELETE | `/tokens/{id}` | admin | Token widerrufen |
