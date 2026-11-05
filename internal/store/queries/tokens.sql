-- name: InsertToken :exec
INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, cidrs, expires_at, created_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(name), sqlc.arg(token_hash), sqlc.arg(scopes),
        sqlc.arg(cidrs), sqlc.arg(expires_at), sqlc.arg(created_at));

-- name: GetToken :one
SELECT id, user_id, name, token_hash, scopes, cidrs, expires_at, last_used_at, created_at
FROM api_tokens WHERE id = sqlc.arg(id);

-- name: ListTokens :many
SELECT id, user_id, name, token_hash, scopes, cidrs, expires_at, last_used_at, created_at
FROM api_tokens ORDER BY created_at DESC, id DESC;

-- name: ListTokensByUser :many
SELECT id, user_id, name, token_hash, scopes, cidrs, expires_at, last_used_at, created_at
FROM api_tokens WHERE user_id = sqlc.arg(user_id) ORDER BY created_at DESC, id DESC;

-- name: TouchToken :exec
UPDATE api_tokens SET last_used_at = sqlc.arg(at) WHERE id = sqlc.arg(id);

-- name: DeleteToken :execrows
DELETE FROM api_tokens WHERE id = sqlc.arg(id);
