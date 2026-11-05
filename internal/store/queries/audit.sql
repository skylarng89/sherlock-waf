-- Taking the audit_head row is what serialises audit writers: on PostgreSQL the
-- UPDATE holds a row lock until the transaction ends, on SQLite there is a single
-- writer anyway. It returns the NEW seq and the hash of the PREVIOUS entry.
-- name: BumpAuditHead :one
UPDATE audit_head SET seq = seq + 1 WHERE id = 1 RETURNING seq, hash;

-- name: SetAuditHeadHash :exec
UPDATE audit_head SET hash = sqlc.arg(hash) WHERE id = 1;

-- name: GetAuditHead :one
SELECT seq, hash FROM audit_head WHERE id = 1;

-- name: InsertAuditEntry :exec
INSERT INTO audit_log (seq, id, at, actor_type, actor_id, ip, action, object_type, object_id, details, prev_hash, hash)
VALUES (sqlc.arg(seq), sqlc.arg(id), sqlc.arg(at), sqlc.arg(actor_type), sqlc.arg(actor_id), sqlc.arg(ip),
        sqlc.arg(action), sqlc.arg(object_type), sqlc.arg(object_id), sqlc.arg(details), sqlc.arg(prev_hash), sqlc.arg(hash));

-- name: ListAuditEntriesDesc :many
SELECT seq, id, at, actor_type, actor_id, ip, action, object_type, object_id, details, prev_hash, hash
FROM audit_log WHERE seq < sqlc.arg(before_seq) ORDER BY seq DESC LIMIT sqlc.arg(max_rows);

-- name: ListAuditEntriesAsc :many
SELECT seq, id, at, actor_type, actor_id, ip, action, object_type, object_id, details, prev_hash, hash
FROM audit_log WHERE seq > sqlc.arg(after_seq) ORDER BY seq ASC LIMIT sqlc.arg(max_rows);
