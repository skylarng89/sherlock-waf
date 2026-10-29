-- name: InsertSession :exec
INSERT INTO sessions (id, user_id, stage, created_at, last_seen_at, expires_at, ip, user_agent, csrf_token_hash)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(stage), sqlc.arg(created_at), sqlc.arg(last_seen_at),
        sqlc.arg(expires_at), sqlc.arg(ip), sqlc.arg(user_agent), sqlc.arg(csrf_token_hash));

-- name: GetSession :one
SELECT id, user_id, stage, created_at, last_seen_at, expires_at, ip, user_agent, csrf_token_hash
FROM sessions WHERE id = sqlc.arg(id);

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = sqlc.arg(at) WHERE id = sqlc.arg(id);

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = sqlc.arg(id);

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = sqlc.arg(user_id);

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at < sqlc.arg(now) OR last_seen_at < sqlc.arg(idle_before);
