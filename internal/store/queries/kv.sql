-- name: GetKV :one
SELECT value FROM kv WHERE key = sqlc.arg(key);

-- name: SetKV :exec
INSERT INTO kv (key, value) VALUES (sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: DeleteKV :exec
DELETE FROM kv WHERE key = sqlc.arg(key);
