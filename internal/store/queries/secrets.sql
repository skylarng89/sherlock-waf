-- name: InsertSecret :exec
INSERT INTO secrets (id, purpose, key_id, nonce, ciphertext, created_at)
VALUES (sqlc.arg(id), sqlc.arg(purpose), sqlc.arg(key_id), sqlc.arg(nonce), sqlc.arg(ciphertext), sqlc.arg(created_at));

-- name: GetSecret :one
SELECT id, purpose, key_id, nonce, ciphertext, created_at FROM secrets WHERE id = sqlc.arg(id);

-- name: ListSecrets :many
SELECT id, purpose, key_id, nonce, ciphertext, created_at FROM secrets ORDER BY id;

-- name: UpdateSecret :execrows
UPDATE secrets SET key_id = sqlc.arg(key_id), nonce = sqlc.arg(nonce), ciphertext = sqlc.arg(ciphertext)
WHERE id = sqlc.arg(id);

-- name: DeleteSecret :exec
DELETE FROM secrets WHERE id = sqlc.arg(id);

-- name: CountSecrets :one
SELECT count(*) FROM secrets;
