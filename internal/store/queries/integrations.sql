-- name: InsertIntegration :exec
INSERT INTO integrations (kind, id, name, type, stream, enabled, secret_id, created_at, updated_at)
VALUES (sqlc.arg(kind), sqlc.arg(id), sqlc.arg(name), sqlc.arg(type), sqlc.arg(stream), sqlc.arg(enabled),
        sqlc.arg(secret_id), sqlc.arg(created_at), sqlc.arg(updated_at));

-- name: UpdateIntegration :execrows
UPDATE integrations SET name = sqlc.arg(name), type = sqlc.arg(type), stream = sqlc.arg(stream),
    enabled = sqlc.arg(enabled), secret_id = sqlc.arg(secret_id), updated_at = sqlc.arg(updated_at)
WHERE kind = sqlc.arg(kind) AND id = sqlc.arg(id);

-- name: GetIntegration :one
SELECT kind, id, name, type, stream, enabled, secret_id, created_at, updated_at
FROM integrations WHERE kind = sqlc.arg(kind) AND id = sqlc.arg(id);

-- name: ListIntegrations :many
SELECT kind, id, name, type, stream, enabled, secret_id, created_at, updated_at
FROM integrations WHERE kind = sqlc.arg(kind) ORDER BY name, id;

-- name: DeleteIntegration :execrows
DELETE FROM integrations WHERE kind = sqlc.arg(kind) AND id = sqlc.arg(id);
