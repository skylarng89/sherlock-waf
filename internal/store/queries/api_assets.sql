-- name: UpsertOpenAPIDoc :exec
INSERT INTO openapi_docs (id, name, version, sha256, body, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(version), sqlc.arg(sha256), sqlc.arg(body), sqlc.arg(updated_at))
ON CONFLICT (id) DO UPDATE SET name = excluded.name, version = excluded.version, sha256 = excluded.sha256,
    body = excluded.body, updated_at = excluded.updated_at;

-- name: GetOpenAPIDoc :one
SELECT id, name, version, sha256, body, updated_at FROM openapi_docs WHERE id = sqlc.arg(id);

-- name: ListOpenAPIDocs :many
SELECT id, name, version, sha256, body, updated_at FROM openapi_docs ORDER BY name, id;

-- name: DeleteOpenAPIDoc :execrows
DELETE FROM openapi_docs WHERE id = sqlc.arg(id);

-- name: InsertCABundle :exec
INSERT INTO ca_bundles (id, name, subjects, fingerprint, pem, not_after, created_at)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(subjects), sqlc.arg(fingerprint), sqlc.arg(pem), sqlc.arg(not_after), sqlc.arg(created_at));

-- name: GetCABundle :one
SELECT id, name, subjects, fingerprint, pem, not_after, created_at FROM ca_bundles WHERE id = sqlc.arg(id);

-- name: ListCABundles :many
SELECT id, name, subjects, fingerprint, pem, not_after, created_at FROM ca_bundles ORDER BY name, id;

-- name: DeleteCABundle :execrows
DELETE FROM ca_bundles WHERE id = sqlc.arg(id);
