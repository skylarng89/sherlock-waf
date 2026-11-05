-- name: GetConfigHeadID :one
SELECT version_id FROM config_head WHERE id = 1;

-- name: CompareAndSetConfigHead :execrows
UPDATE config_head SET version_id = sqlc.arg(new_id)
WHERE id = 1 AND version_id = sqlc.arg(expected_id);

-- name: InsertConfigVersion :exec
INSERT INTO config_versions (id, parent_id, created_at, author_type, author_id, source, schema_version, snapshot, diff, applied)
VALUES (sqlc.arg(id), sqlc.arg(parent_id), sqlc.arg(created_at), sqlc.arg(author_type), sqlc.arg(author_id),
        sqlc.arg(source), sqlc.arg(schema_version), sqlc.arg(snapshot), sqlc.arg(diff), sqlc.arg(applied));

-- name: GetConfigVersion :one
SELECT id, parent_id, created_at, author_type, author_id, source, schema_version, snapshot, diff, applied
FROM config_versions WHERE id = sqlc.arg(id);

-- name: ListConfigVersions :many
SELECT id, parent_id, created_at, author_type, author_id, source, schema_version, snapshot, diff, applied
FROM config_versions
WHERE created_at < sqlc.arg(before_ts) OR (created_at = sqlc.arg(before_ts) AND id < sqlc.arg(before_id))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: DeleteAllSites :exec
DELETE FROM sites;

-- name: InsertSite :exec
INSERT INTO sites (id, name, mode, hosts, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(mode), sqlc.arg(hosts), sqlc.arg(updated_at));

-- name: ListSites :many
SELECT id, name, mode, hosts, updated_at FROM sites ORDER BY id;
