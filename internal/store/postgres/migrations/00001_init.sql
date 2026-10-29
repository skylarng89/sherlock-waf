-- +goose Up
-- Initial schema (postgres). Keep in step with the other dialect's 00001: a CI check compares version numbers.

-- Every timestamp is BIGINT unix microseconds, set from Go, never by the database
-- (portable, deterministic in tests, and exact for the audit hash).
-- Ids are text ULIDs or user-chosen slugs. Enumerations are TEXT + CHECK.
-- JSON is stored as TEXT so the bytes that were hashed or diffed are the bytes read back.

CREATE TABLE config_versions (
    id             TEXT   PRIMARY KEY,
    parent_id      TEXT   NOT NULL DEFAULT '',
    created_at     BIGINT NOT NULL,
    author_type    TEXT   NOT NULL CHECK (author_type IN ('user', 'token', 'system', 'cli')),
    author_id      TEXT   NOT NULL,
    source         TEXT   NOT NULL CHECK (source IN ('api', 'import', 'rollback', 'cli', 'boot')),
    schema_version BIGINT NOT NULL,
    snapshot       TEXT   NOT NULL,
    diff           TEXT   NOT NULL,
    applied        BIGINT NOT NULL CHECK (applied IN (0, 1))
);
CREATE INDEX config_versions_created ON config_versions (created_at, id);

-- One row. version_id is '' until the first version is applied; the empty string
-- (not NULL) keeps the compare-and-swap UPDATE identical on both dialects.
CREATE TABLE config_head (
    id         BIGINT PRIMARY KEY CHECK (id = 1),
    version_id TEXT   NOT NULL
);
INSERT INTO config_head (id, version_id) VALUES (1, '');

-- Projection of the head snapshot for listing and filtering; the snapshot wins.
CREATE TABLE sites (
    id         TEXT   PRIMARY KEY,
    name       TEXT   NOT NULL,
    mode       TEXT   NOT NULL,
    hosts      TEXT   NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE secrets (
    id         TEXT   PRIMARY KEY,
    purpose    TEXT   NOT NULL,
    key_id     BIGINT NOT NULL,
    nonce      BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE users (
    id            TEXT   PRIMARY KEY,
    username      TEXT   NOT NULL UNIQUE,
    password_hash TEXT   NOT NULL,
    role          TEXT   NOT NULL CHECK (role IN ('admin', 'viewer')),
    mfa_secret_id TEXT   NOT NULL DEFAULT '',
    mfa_enabled   BIGINT NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
    mfa_last_step BIGINT NOT NULL DEFAULT 0,
    disabled      BIGINT NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    failed_count  BIGINT NOT NULL DEFAULT 0,
    locked_until  BIGINT NOT NULL DEFAULT 0,
    last_login_at BIGINT NOT NULL DEFAULT 0,
    created_at    BIGINT NOT NULL
);

-- id is the SHA-256 (hex) of the session token; the token itself is never stored.
CREATE TABLE sessions (
    id              TEXT   PRIMARY KEY,
    user_id         TEXT   NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    stage           TEXT   NOT NULL CHECK (stage IN ('password_ok', 'mfa_enrol_required', 'full')),
    created_at      BIGINT NOT NULL,
    last_seen_at    BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    ip              TEXT   NOT NULL,
    user_agent      TEXT   NOT NULL,
    csrf_token_hash TEXT   NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE api_tokens (
    id           TEXT   PRIMARY KEY,
    user_id      TEXT   NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT   NOT NULL,
    token_hash   TEXT   NOT NULL,
    scopes       TEXT   NOT NULL,
    cidrs        TEXT   NOT NULL,
    expires_at   BIGINT NOT NULL DEFAULT 0,
    last_used_at BIGINT NOT NULL DEFAULT 0,
    created_at   BIGINT NOT NULL
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

-- seq gives a strict order (ULIDs are not strictly monotonic) and is what the
-- hash chain is walked by. hash covers prev_hash and every other column.
CREATE TABLE audit_log (
    seq         BIGINT PRIMARY KEY,
    id          TEXT   NOT NULL UNIQUE,
    at          BIGINT NOT NULL,
    actor_type  TEXT   NOT NULL CHECK (actor_type IN ('user', 'token', 'system')),
    actor_id    TEXT   NOT NULL,
    ip          TEXT   NOT NULL,
    action      TEXT   NOT NULL,
    object_type TEXT   NOT NULL,
    object_id   TEXT   NOT NULL,
    details     TEXT   NOT NULL,
    prev_hash   TEXT   NOT NULL,
    hash        TEXT   NOT NULL
);

-- One row: its UPDATE is the lock that serialises audit writers.
CREATE TABLE audit_head (
    id   BIGINT PRIMARY KEY CHECK (id = 1),
    seq  BIGINT NOT NULL,
    hash TEXT   NOT NULL
);
INSERT INTO audit_head (id, seq, hash) VALUES (1, 0, '');

CREATE TABLE events (
    id         TEXT   PRIMARY KEY,
    ts         BIGINT NOT NULL,
    site_id    TEXT   NOT NULL,
    action     TEXT   NOT NULL,
    mode       TEXT   NOT NULL,
    client_ip  TEXT   NOT NULL,
    method     TEXT   NOT NULL,
    host       TEXT   NOT NULL,
    path       TEXT   NOT NULL,
    status     BIGINT NOT NULL,
    rule_ids   TEXT   NOT NULL,
    body       TEXT   NOT NULL
);
CREATE INDEX events_ts ON events (ts, id);
CREATE INDEX events_site_ts ON events (site_id, ts);
CREATE INDEX events_ip_ts ON events (client_ip, ts);

CREATE TABLE event_rollups_1m (
    bucket  BIGINT NOT NULL,
    site_id TEXT   NOT NULL,
    action  TEXT   NOT NULL,
    count   BIGINT NOT NULL,
    PRIMARY KEY (bucket, site_id, action)
);

CREATE TABLE kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- +goose Down

DROP TABLE kv;
DROP TABLE event_rollups_1m;
DROP TABLE events;
DROP TABLE audit_head;
DROP TABLE audit_log;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE secrets;
DROP TABLE sites;
DROP TABLE config_head;
DROP TABLE config_versions;
