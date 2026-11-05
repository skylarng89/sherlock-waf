-- +goose Up
-- Country of the client at event time (from the GeoIP database; '' when unknown),
-- stored as a column so the attack explorer and analytics can filter and group on it.
ALTER TABLE events ADD COLUMN country TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE events DROP COLUMN country;
