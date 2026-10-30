-- +goose Up
-- API protection assets (M9): uploaded OpenAPI documents and the CA bundles
-- that verify client certificates. Both are referenced from the configuration
-- by id, like certificates and block pages (ADR-0016).

CREATE TABLE openapi_docs (
    id         TEXT   PRIMARY KEY,
    name       TEXT   NOT NULL,
    version    TEXT   NOT NULL,
    sha256     TEXT   NOT NULL,
    body       TEXT   NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE ca_bundles (
    id          TEXT   PRIMARY KEY,
    name        TEXT   NOT NULL,
    subjects    TEXT   NOT NULL,
    fingerprint TEXT   NOT NULL,
    pem         TEXT   NOT NULL,
    not_after   BIGINT NOT NULL,
    created_at  BIGINT NOT NULL
);

-- +goose Down
DROP TABLE ca_bundles;
DROP TABLE openapi_docs;
