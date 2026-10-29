-- name: InsertEvent :exec
INSERT INTO events (id, ts, site_id, action, mode, client_ip, method, host, path, status, rule_ids, body, country)
VALUES (sqlc.arg(id), sqlc.arg(ts), sqlc.arg(site_id), sqlc.arg(action), sqlc.arg(mode), sqlc.arg(client_ip),
        sqlc.arg(method), sqlc.arg(host), sqlc.arg(path), sqlc.arg(status), sqlc.arg(rule_ids), sqlc.arg(body), sqlc.arg(country))
ON CONFLICT (id) DO NOTHING;

-- name: GetEvent :one
SELECT id, ts, site_id, action, mode, client_ip, method, host, path, status, rule_ids, body, country
FROM events WHERE id = sqlc.arg(id);

-- Optional filters are NULL when unused. CAST keeps the NULL checks valid on both dialects.
-- name: ListEvents :many
SELECT id, ts, site_id, action, mode, client_ip, method, host, path, status, rule_ids, body, country
FROM events
WHERE (ts < sqlc.arg(before_ts) OR (ts = sqlc.arg(before_ts) AND id < sqlc.arg(before_id)))
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
  AND (CAST(sqlc.narg(client_ip) AS TEXT) IS NULL OR client_ip = CAST(sqlc.narg(client_ip) AS TEXT))
  AND (CAST(sqlc.narg(rule_id) AS TEXT) IS NULL OR rule_ids LIKE '% ' || CAST(sqlc.narg(rule_id) AS TEXT) || ' %')
  AND (CAST(sqlc.narg(from_ts) AS BIGINT) IS NULL OR ts >= CAST(sqlc.narg(from_ts) AS BIGINT))
  AND (CAST(sqlc.narg(to_ts) AS BIGINT) IS NULL OR ts < CAST(sqlc.narg(to_ts) AS BIGINT))
  AND (CAST(sqlc.narg(country) AS TEXT) IS NULL OR country = CAST(sqlc.narg(country) AS TEXT))
  AND (CAST(sqlc.narg(method) AS TEXT) IS NULL OR method = CAST(sqlc.narg(method) AS TEXT))
  AND (CAST(sqlc.narg(status) AS BIGINT) IS NULL OR status = CAST(sqlc.narg(status) AS BIGINT))
  AND (CAST(sqlc.narg(mode) AS TEXT) IS NULL OR mode = CAST(sqlc.narg(mode) AS TEXT))
  AND (CAST(sqlc.narg(text) AS TEXT) IS NULL
       OR lower(path) LIKE '%' || lower(CAST(sqlc.narg(text) AS TEXT)) || '%' ESCAPE '\'
       OR lower(host) LIKE '%' || lower(CAST(sqlc.narg(text) AS TEXT)) || '%' ESCAPE '\'
       OR client_ip LIKE '%' || CAST(sqlc.narg(text) AS TEXT) || '%' ESCAPE '\'
       OR rule_ids LIKE '%' || CAST(sqlc.narg(text) AS TEXT) || '%' ESCAPE '\')
ORDER BY ts DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: CountEvents :one
SELECT count(*) FROM events;

-- name: DeleteEventsBefore :execrows
DELETE FROM events WHERE id IN (SELECT old.id FROM events old WHERE old.ts < sqlc.arg(cutoff) ORDER BY old.ts LIMIT sqlc.arg(max_rows));

-- name: AddRollup :exec
INSERT INTO event_rollups_1m (bucket, site_id, action, count)
VALUES (sqlc.arg(bucket), sqlc.arg(site_id), sqlc.arg(action), sqlc.arg(count))
ON CONFLICT (bucket, site_id, action) DO UPDATE SET count = event_rollups_1m.count + excluded.count;

-- name: ListRollups :many
SELECT bucket, site_id, action, count FROM event_rollups_1m
WHERE bucket >= sqlc.arg(from_bucket) AND bucket < sqlc.arg(to_bucket) ORDER BY bucket, site_id, action;

-- name: DeleteRollupsBefore :execrows
DELETE FROM event_rollups_1m WHERE bucket < sqlc.arg(cutoff);

-- name: TopEventIPs :many
SELECT client_ip AS value, count(*) AS n FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) 
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT sqlc.arg(max_rows);

-- name: TopEventPaths :many
SELECT path AS value, count(*) AS n FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) 
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
GROUP BY path ORDER BY n DESC, path LIMIT sqlc.arg(max_rows);

-- name: TopEventCountries :many
SELECT country AS value, count(*) AS n FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) AND country <> ''
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
GROUP BY country ORDER BY n DESC, country LIMIT sqlc.arg(max_rows);

-- name: TopEventSites :many
SELECT site_id AS value, count(*) AS n FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) 
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
GROUP BY site_id ORDER BY n DESC, site_id LIMIT sqlc.arg(max_rows);

-- name: TopEventActions :many
SELECT action AS value, count(*) AS n FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) 
  AND (CAST(sqlc.narg(site_id) AS TEXT) IS NULL OR site_id = CAST(sqlc.narg(site_id) AS TEXT))
  AND (CAST(sqlc.narg(action) AS TEXT) IS NULL OR action = CAST(sqlc.narg(action) AS TEXT))
GROUP BY action ORDER BY n DESC, action LIMIT sqlc.arg(max_rows);
