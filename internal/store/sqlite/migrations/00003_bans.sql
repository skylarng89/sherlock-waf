-- +goose Up
-- Temporary bans (M5). The data plane keeps the live set in memory; this table is
-- what survives a restart and what the dashboard lists. site_id '' means every site.

CREATE TABLE bans (
    id         TEXT   PRIMARY KEY,
    ip         TEXT   NOT NULL,
    site_id    TEXT   NOT NULL DEFAULT '',
    source     TEXT   NOT NULL CHECK (source IN ('manual', 'auto', 'crowdsec')),
    reason     TEXT   NOT NULL,
    created_by TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    until      BIGINT NOT NULL,
    UNIQUE (ip, site_id)
);
CREATE INDEX bans_until ON bans (until);

-- +goose Down
DROP TABLE bans;
