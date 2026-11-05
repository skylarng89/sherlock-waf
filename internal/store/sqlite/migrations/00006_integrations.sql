-- +goose Up
-- SIEM exporters, notification channels and alert rules (M10). They share one
-- table because they share a lifecycle: a named, typed, switchable object whose
-- settings may carry credentials. The whole settings document is encrypted as
-- one secret (secret_id), so no column ever holds a webhook URL, an HMAC key or
-- an SMTP password in clear text.

CREATE TABLE integrations (
    kind       TEXT   NOT NULL CHECK (kind IN ('exporter', 'channel', 'alert_rule')),
    id         TEXT   NOT NULL,
    name       TEXT   NOT NULL,
    type       TEXT   NOT NULL,
    stream     TEXT   NOT NULL DEFAULT '',
    enabled    BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    secret_id  TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (kind, id),
    UNIQUE (kind, name)
);

-- +goose Down
DROP TABLE integrations;
