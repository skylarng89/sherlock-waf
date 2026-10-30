-- name: InsertUser :exec
INSERT INTO users (id, username, password_hash, role, created_at)
VALUES (sqlc.arg(id), sqlc.arg(username), sqlc.arg(password_hash), sqlc.arg(role), sqlc.arg(created_at));

-- name: GetUserByID :one
SELECT id, username, password_hash, role, mfa_secret_id, mfa_enabled, mfa_last_step, disabled,
       failed_count, locked_until, last_login_at, created_at
FROM users WHERE id = sqlc.arg(id);

-- name: GetUserByUsername :one
SELECT id, username, password_hash, role, mfa_secret_id, mfa_enabled, mfa_last_step, disabled,
       failed_count, locked_until, last_login_at, created_at
FROM users WHERE username = sqlc.arg(username);

-- name: ListUsers :many
SELECT id, username, password_hash, role, mfa_secret_id, mfa_enabled, mfa_last_step, disabled,
       failed_count, locked_until, last_login_at, created_at
FROM users ORDER BY username;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: UpdateUserPassword :execrows
UPDATE users SET password_hash = sqlc.arg(password_hash), failed_count = 0, locked_until = 0 WHERE id = sqlc.arg(id);

-- name: UpdateUserRole :execrows
UPDATE users SET role = sqlc.arg(role) WHERE id = sqlc.arg(id);

-- name: SetUserDisabled :execrows
UPDATE users SET disabled = sqlc.arg(disabled) WHERE id = sqlc.arg(id);

-- name: SetUserMFA :execrows
UPDATE users SET mfa_secret_id = sqlc.arg(mfa_secret_id), mfa_enabled = sqlc.arg(mfa_enabled), mfa_last_step = 0
WHERE id = sqlc.arg(id);

-- Accepts a TOTP step only if it is newer than the last accepted one (replay protection).
-- name: AdvanceUserMFAStep :execrows
UPDATE users SET mfa_last_step = sqlc.arg(step) WHERE id = sqlc.arg(id) AND mfa_last_step < sqlc.arg(step);

-- name: RecordLoginFailure :exec
UPDATE users SET failed_count = sqlc.arg(failed_count), locked_until = sqlc.arg(locked_until) WHERE id = sqlc.arg(id);

-- name: RecordLoginSuccess :exec
UPDATE users SET failed_count = 0, locked_until = 0, last_login_at = sqlc.arg(at) WHERE id = sqlc.arg(id);

-- name: UnlockUser :exec
UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = sqlc.arg(id);

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = sqlc.arg(id);
