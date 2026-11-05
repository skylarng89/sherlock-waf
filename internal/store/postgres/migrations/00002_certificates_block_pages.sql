-- +goose Up
-- Uploaded certificates and custom block page templates (M4). Private keys are
-- not stored here: key_secret_id points at an encrypted row in secrets.

CREATE TABLE certificates (
    id            TEXT   PRIMARY KEY,
    name          TEXT   NOT NULL UNIQUE,
    hosts         TEXT   NOT NULL,
    not_before    BIGINT NOT NULL,
    not_after     BIGINT NOT NULL,
    issuer        TEXT   NOT NULL,
    fingerprint   TEXT   NOT NULL,
    chain_pem     TEXT   NOT NULL,
    key_secret_id TEXT   NOT NULL REFERENCES secrets (id),
    created_at    BIGINT NOT NULL
);

CREATE TABLE block_pages (
    id         TEXT   PRIMARY KEY,
    html       TEXT   NOT NULL,
    updated_at BIGINT NOT NULL
);

-- +goose Down
DROP TABLE block_pages;
DROP TABLE certificates;
