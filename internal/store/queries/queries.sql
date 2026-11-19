-- == settings ==
-- name: GetSetting :one
SELECT * FROM settings WHERE key = ?;

-- name: ListSettings :many
SELECT * FROM settings ORDER BY key;

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, version, updated_at) VALUES (?, ?, 1, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, version = settings.version + 1, updated_at = excluded.updated_at;

-- == sites ==
-- name: ListSites :many
SELECT * FROM sites ORDER BY name;

-- name: GetSite :one
SELECT * FROM sites WHERE name = ?;

-- name: InsertSite :exec
INSERT INTO sites (name, subnet, connector_ip, lan_cidr, public_key, psk_enc, os_hint, email, enabled, status, last_seen_at, notes, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: UpdateSite :execrows
UPDATE sites SET lan_cidr = ?, public_key = ?, psk_enc = ?, os_hint = ?, email = ?, enabled = ?, status = ?, notes = ?,
  version = version + 1, updated_at = ?
WHERE name = ? AND version = ?;

-- name: UpdateSiteStatus :exec
UPDATE sites SET status = ?, last_seen_at = ? WHERE name = ?;

-- name: DeleteSite :execrows
DELETE FROM sites WHERE name = ? AND version = ?;

-- name: CountHostsBySite :one
SELECT COUNT(*) FROM hosts WHERE site_name = ?;

-- == hosts ==
-- name: ListHosts :many
SELECT * FROM hosts ORDER BY fqdn;

-- name: GetHost :one
SELECT * FROM hosts WHERE fqdn = ?;

-- name: InsertHost :exec
INSERT INTO hosts (fqdn, upstream_scheme, upstream_address, upstream_port, site_name, external_port, websockets, waf,
  client_max_body_size, hsts_json, acme_email, status, status_detail, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: UpdateHost :execrows
UPDATE hosts SET upstream_scheme = ?, upstream_address = ?, upstream_port = ?, site_name = ?, external_port = ?,
  websockets = ?, waf = ?, client_max_body_size = ?, hsts_json = ?, acme_email = ?, status = ?, status_detail = ?,
  version = version + 1, updated_at = ?
WHERE fqdn = ? AND version = ?;

-- name: SetHostStatus :exec
UPDATE hosts SET status = ?, status_detail = ? WHERE fqdn = ?;

-- name: DeleteHost :execrows
DELETE FROM hosts WHERE fqdn = ? AND version = ?;

-- == certificates ==
-- name: ListCertificates :many
SELECT * FROM certificates ORDER BY fqdn;

-- name: GetCertificate :one
SELECT * FROM certificates WHERE fqdn = ?;

-- name: UpsertCertificate :exec
INSERT INTO certificates (fqdn, chain_pem, key_enc, not_before, not_after, ari_renew_at, issuer, source, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (fqdn) DO UPDATE SET chain_pem = excluded.chain_pem, key_enc = excluded.key_enc,
  not_before = excluded.not_before, not_after = excluded.not_after, ari_renew_at = excluded.ari_renew_at,
  issuer = excluded.issuer, source = excluded.source, updated_at = excluded.updated_at;

-- name: SetCertificateRenewAt :exec
UPDATE certificates SET ari_renew_at = ? WHERE fqdn = ?;

-- name: DeleteCertificate :execrows
DELETE FROM certificates WHERE fqdn = ?;

-- == acme ==
-- name: GetAcmeAccount :one
SELECT * FROM acme_accounts WHERE directory = ?;

-- name: UpsertAcmeAccount :exec
INSERT INTO acme_accounts (directory, email, key_enc, reg_json, created_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (directory) DO UPDATE SET email = excluded.email, key_enc = excluded.key_enc, reg_json = excluded.reg_json;

-- == wireguard hub ==
-- name: GetWgHub :one
SELECT * FROM wg_hub WHERE id = 1;

-- name: UpsertWgHub :exec
INSERT INTO wg_hub (id, private_key_enc, public_key, listen_port, address, overlay_cidr) VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET private_key_enc = excluded.private_key_enc, public_key = excluded.public_key,
  listen_port = excluded.listen_port, address = excluded.address, overlay_cidr = excluded.overlay_cidr;

-- == jobs ==
-- name: InsertJob :exec
INSERT INTO jobs (id, kind, resource, status, attempts, created_by, created_at, run_after)
VALUES (?, ?, ?, 'queued', 0, ?, ?, ?);

-- name: GetJob :one
SELECT * FROM jobs WHERE id = ?;

-- name: ListJobs :many
SELECT * FROM jobs
WHERE (sqlc.narg('status') IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('cursor') IS NULL OR id < sqlc.narg('cursor'))
ORDER BY id DESC LIMIT sqlc.arg('lim');

-- name: ListDueJobs :many
SELECT * FROM jobs WHERE status = 'queued' AND run_after <= ? ORDER BY id LIMIT 50;

-- name: ClaimJob :execrows
UPDATE jobs SET status = 'running', attempts = attempts + 1, started_at = ?, error = NULL
WHERE id = ? AND status = 'queued';

-- name: FinishJob :exec
UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?;

-- name: RetryJob :exec
UPDATE jobs SET status = 'queued', error = ?, run_after = ? WHERE id = ?;

-- name: ResetRunningJobs :exec
UPDATE jobs SET status = 'queued' WHERE status = 'running';

-- name: CountOpenJobsFor :one
SELECT COUNT(*) FROM jobs WHERE resource = ? AND kind = ? AND status IN ('queued','running');

-- name: CountJobsByStatus :many
SELECT status, COUNT(*) AS n FROM jobs GROUP BY status;

-- name: PruneJobs :exec
DELETE FROM jobs WHERE status IN ('succeeded','failed') AND finished_at < ?;

-- == api clients ==
-- name: InsertClient :exec
INSERT INTO api_clients (id, name, role, cert_sha256, serial, not_after, disabled, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?);

-- name: GetClientByFingerprint :one
SELECT * FROM api_clients WHERE cert_sha256 = ?;

-- name: GetClientByName :one
SELECT * FROM api_clients WHERE name = ?;

-- name: ListClients :many
SELECT * FROM api_clients ORDER BY name;

-- name: UpdateClientCert :exec
UPDATE api_clients SET cert_sha256 = ?, serial = ?, not_after = ?, disabled = 0 WHERE name = ?;

-- name: DisableClient :execrows
UPDATE api_clients SET disabled = 1 WHERE name = ?;

-- name: DeleteClient :execrows
DELETE FROM api_clients WHERE name = ?;

-- name: TouchClient :exec
UPDATE api_clients SET last_used_at = ? WHERE id = ?;

-- == api tokens ==
-- name: InsertToken :exec
INSERT INTO api_tokens (id, name, role, secret_sha256, expires_at, disabled, created_by, created_at)
VALUES (?, ?, ?, ?, ?, 0, ?, ?);

-- name: GetToken :one
SELECT * FROM api_tokens WHERE id = ?;

-- name: ListTokens :many
SELECT * FROM api_tokens ORDER BY created_at;

-- name: DisableToken :execrows
UPDATE api_tokens SET disabled = 1 WHERE id = ?;

-- name: TouchToken :exec
UPDATE api_tokens SET last_used_at = ? WHERE id = ?;

-- == pki ==
-- name: GetPki :one
SELECT * FROM pki WHERE id = 1;

-- name: UpsertPki :exec
INSERT INTO pki (id, ca_cert_pem, ca_key_enc, server_cert_pem, server_key_enc) VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET ca_cert_pem = excluded.ca_cert_pem, ca_key_enc = excluded.ca_key_enc,
  server_cert_pem = excluded.server_cert_pem, server_key_enc = excluded.server_key_enc;

-- == idempotency ==
-- name: GetIdempotencyKey :one
SELECT * FROM idempotency_keys WHERE key = ? AND actor = ?;

-- name: InsertIdempotencyKey :exec
INSERT OR IGNORE INTO idempotency_keys (key, actor, status, headers, response, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: PruneIdempotencyKeys :exec
DELETE FROM idempotency_keys WHERE created_at < ?;

-- == render generations ==
-- name: MaxGenerationID :one
SELECT CAST(COALESCE(MAX(id), 0) AS INTEGER) FROM render_generations;

-- name: InsertGeneration :exec
INSERT INTO render_generations (id, content_sha256, status, nginx_test_output, created_at) VALUES (?, ?, ?, ?, ?);

-- name: SetGenerationStatus :exec
UPDATE render_generations SET status = ? WHERE id = ?;

-- name: ListGenerations :many
SELECT * FROM render_generations ORDER BY id DESC LIMIT ?;

-- name: PruneGenerations :exec
DELETE FROM render_generations WHERE id <= ?;

-- == audit ==
-- name: LastAuditEntry :one
SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1;

-- name: InsertAudit :one
INSERT INTO audit_log (ts, request_id, actor_type, actor_id, actor_fingerprint, source_ip, action, resource_type,
  resource_id, before_json, after_json, result, error, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING seq;

-- name: ListAudit :many
SELECT * FROM audit_log
WHERE (sqlc.narg('since') IS NULL OR ts >= sqlc.narg('since'))
  AND (sqlc.narg('actor') IS NULL OR actor_id = sqlc.narg('actor'))
  AND (sqlc.narg('resource') IS NULL OR resource_id = sqlc.narg('resource') OR resource_type = sqlc.narg('resource'))
  AND (sqlc.narg('cursor') IS NULL OR seq < sqlc.narg('cursor'))
ORDER BY seq DESC LIMIT sqlc.arg('lim');

-- name: ListAuditAsc :many
SELECT * FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?;

-- name: LastAuditBefore :one
SELECT * FROM audit_log WHERE ts < ? ORDER BY seq DESC LIMIT 1;

-- name: DeleteAuditUpTo :execrows
DELETE FROM audit_log WHERE seq <= ?;

-- name: FindPruneAnchor :one
SELECT COUNT(*) FROM audit_log WHERE action = 'audit.prune' AND resource_id = ?;
