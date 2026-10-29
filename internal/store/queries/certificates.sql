-- name: InsertCertificate :exec
INSERT INTO certificates (id, name, hosts, not_before, not_after, issuer, fingerprint, chain_pem, key_secret_id, created_at)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(hosts), sqlc.arg(not_before), sqlc.arg(not_after), sqlc.arg(issuer),
        sqlc.arg(fingerprint), sqlc.arg(chain_pem), sqlc.arg(key_secret_id), sqlc.arg(created_at));

-- name: GetCertificate :one
SELECT id, name, hosts, not_before, not_after, issuer, fingerprint, chain_pem, key_secret_id, created_at
FROM certificates WHERE id = sqlc.arg(id);

-- name: ListCertificates :many
SELECT id, name, hosts, not_before, not_after, issuer, fingerprint, chain_pem, key_secret_id, created_at
FROM certificates ORDER BY name, id;

-- name: DeleteCertificate :execrows
DELETE FROM certificates WHERE id = sqlc.arg(id);

-- name: UpsertBlockPage :exec
INSERT INTO block_pages (id, html, updated_at) VALUES (sqlc.arg(id), sqlc.arg(html), sqlc.arg(updated_at))
ON CONFLICT (id) DO UPDATE SET html = excluded.html, updated_at = excluded.updated_at;

-- name: GetBlockPage :one
SELECT id, html, updated_at FROM block_pages WHERE id = sqlc.arg(id);

-- name: ListBlockPages :many
SELECT id, html, updated_at FROM block_pages ORDER BY id;

-- name: DeleteBlockPage :execrows
DELETE FROM block_pages WHERE id = sqlc.arg(id);
