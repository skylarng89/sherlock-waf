-- name: UpsertBan :exec
INSERT INTO bans (id, ip, site_id, source, reason, created_by, created_at, until)
VALUES (sqlc.arg(id), sqlc.arg(ip), sqlc.arg(site_id), sqlc.arg(source), sqlc.arg(reason), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(until))
ON CONFLICT (ip, site_id) DO UPDATE SET source = excluded.source, reason = excluded.reason, created_by = excluded.created_by,
    created_at = excluded.created_at, until = excluded.until;

-- name: GetBan :one
SELECT id, ip, site_id, source, reason, created_by, created_at, until FROM bans WHERE id = sqlc.arg(id);

-- name: ListActiveBans :many
SELECT id, ip, site_id, source, reason, created_by, created_at, until FROM bans
WHERE until > sqlc.arg(now_ts) ORDER BY until, id;

-- name: DeleteBan :execrows
DELETE FROM bans WHERE id = sqlc.arg(id);

-- name: DeleteExpiredBans :execrows
DELETE FROM bans WHERE until <= sqlc.arg(now_ts);
