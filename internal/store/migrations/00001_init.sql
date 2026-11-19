-- +goose Up
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  version    INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE sites (
  name          TEXT PRIMARY KEY,
  subnet        TEXT NOT NULL UNIQUE,
  connector_ip  TEXT NOT NULL,
  lan_cidr      TEXT,
  public_key    TEXT,
  psk_enc       BLOB,
  os_hint       TEXT,
  email         TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  status        TEXT NOT NULL DEFAULT 'pending',
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
  client_max_body_size TEXT,
  hsts_json            TEXT,
  acme_email           TEXT,
  status               TEXT NOT NULL DEFAULT 'pending_certificate',
  status_detail        TEXT,
  version              INTEGER NOT NULL DEFAULT 1,
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

-- Kein FK auf hosts: `DELETE /hosts/{fqdn}?keep_cert=true` und der v2-Import
-- brauchen Zertifikate ohne zugehoerigen Host.
CREATE TABLE certificates (
  fqdn         TEXT PRIMARY KEY,
  chain_pem    TEXT NOT NULL,
  key_enc      BLOB NOT NULL,
  not_before   TEXT NOT NULL,
  not_after    TEXT NOT NULL,
  ari_renew_at TEXT,
  issuer       TEXT NOT NULL,
  source       TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE acme_accounts (
  id          INTEGER PRIMARY KEY,
  directory   TEXT NOT NULL UNIQUE,
  email       TEXT,
  key_enc     BLOB NOT NULL,
  reg_json    TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE wg_hub (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  private_key_enc BLOB NOT NULL,
  public_key      TEXT NOT NULL,
  listen_port     INTEGER NOT NULL,
  address         TEXT NOT NULL,
  overlay_cidr    TEXT NOT NULL
);

CREATE TABLE jobs (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,
  resource    TEXT NOT NULL,
  status      TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  error       TEXT,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  run_after   TEXT NOT NULL,
  started_at  TEXT,
  finished_at TEXT
);
CREATE INDEX jobs_status ON jobs(status, run_after);

CREATE TABLE api_clients (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  role          TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
  cert_sha256   TEXT NOT NULL UNIQUE,
  serial        TEXT NOT NULL,
  not_after     TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);

CREATE TABLE api_tokens (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
  secret_sha256 BLOB NOT NULL,
  expires_at    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);

CREATE TABLE pki (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  ca_cert_pem     TEXT NOT NULL,
  ca_key_enc      BLOB NOT NULL,
  server_cert_pem TEXT NOT NULL,
  server_key_enc  BLOB NOT NULL
);

CREATE TABLE idempotency_keys (
  key         TEXT NOT NULL,
  actor       TEXT NOT NULL,
  status      INTEGER NOT NULL,
  headers     TEXT NOT NULL,
  response    BLOB NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (key, actor)
);

CREATE TABLE render_generations (
  id                INTEGER PRIMARY KEY,
  content_sha256    TEXT NOT NULL,
  status            TEXT NOT NULL,
  nginx_test_output TEXT,
  created_at        TEXT NOT NULL
);

CREATE TABLE audit_log (
  seq               INTEGER PRIMARY KEY AUTOINCREMENT,
  ts                TEXT NOT NULL,
  request_id        TEXT NOT NULL,
  actor_type        TEXT NOT NULL,
  actor_id          TEXT NOT NULL,
  actor_fingerprint TEXT,
  source_ip         TEXT,
  action            TEXT NOT NULL,
  resource_type     TEXT NOT NULL,
  resource_id       TEXT,
  before_json       TEXT,
  after_json        TEXT,
  result            TEXT NOT NULL,
  error             TEXT,
  prev_hash         BLOB NOT NULL,
  hash              BLOB NOT NULL
);
CREATE INDEX audit_ts ON audit_log(ts);
CREATE INDEX audit_resource ON audit_log(resource_type, resource_id);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE render_generations;
DROP TABLE idempotency_keys;
DROP TABLE pki;
DROP TABLE api_tokens;
DROP TABLE api_clients;
DROP TABLE jobs;
DROP TABLE wg_hub;
DROP TABLE acme_accounts;
DROP TABLE certificates;
DROP TABLE hosts;
DROP TABLE sites;
DROP TABLE settings;
