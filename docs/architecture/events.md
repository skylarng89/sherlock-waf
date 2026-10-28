# Events

## Event schema (v1)

One event per request that had at least one finding, plus system events (config applied, ban created). Stored in `events`, exported as JSON with the same field names.

| Field | Type | Example | Notes |
| --- | --- | --- | --- |
| `id` | ULID | `01JB…` | Also returned to the client in `X-Sherlock-Event-Id` |
| `schema` | string | `sherlock.event.v1` | |
| `ts` | RFC 3339 nano | | Request start |
| `node` | string | `waf-01` | Node name |
| `site_id` | string | `shop` | |
| `action` | enum | `block` | `allow`, `log`, `challenge`, `block`, `ratelimit`, `ban` |
| `mode` | enum | `detect` | Site mode at that time |
| `terminated_by` | string | `waf` | Empty if proxied |
| `client.ip` | string | `198.51.100.7` | |
| `client.country` | string | `NG` | ISO 3166-1 alpha-2 |
| `client.asn` | int | | If the GeoIP DB provides it |
| `client.reputation` | int 0–100 | | |
| `request.method`, `.host`, `.path`, `.query` | string | | `query` redacted (below) |
| `request.headers` | object | | Allow-list only: `User-Agent`, `Referer`, `Content-Type`, `Content-Length`, `Accept`, `X-Forwarded-For` |
| `request.body_excerpt` | string | | Off by default; when on, first 2 KB, redacted |
| `response.status` | int | `403` | |
| `response.bytes` | int | | |
| `timing.total_ms`, `timing.waf_ms` | float | | |
| `findings[]` | array | | `module`, `rule_id`, `tags`, `severity`, `target`, `matched` (≤256 bytes, redacted), `message`, `score` |
| `anomaly_score.inbound`, `.outbound` | int | | CRS totals |
| `config_version` | ULID | | Which config produced the decision |

The JSON Schema is generated to `docs/reference/event.schema.json`. Exporters MUST emit exactly this schema (CEF mapping below). Changing it requires `sherlock.event.v2` and a dual-write period of one minor release.

## Redaction

Applied before an event leaves the request path:

- Query and body parameters whose names match `(?i)pass|pwd|secret|token|otp|pin|cvv|cvc|card|pan|ssn|authorization` → value replaced with `[REDACTED]`.
- Any value matching a Luhn-valid 13–19 digit sequence → `[PAN:****1234]` (last four only).
- `Authorization` and `Cookie` headers are never captured.
- Users can add redaction patterns globally.

## Pipeline

1. `sherlock_core` builds the event after the response is written and calls `bus.Publish(ev)`.
2. The bus is a bounded ring buffer (default 65,536 events). `Publish` never blocks; on overflow it drops the oldest event and increments `sherlock_events_dropped_total`. A dropped event still increments rollup counters, so charts stay correct.
3. The **batch writer** drains every 1 s or every 500 events into the event store in one transaction and updates `event_rollups_1m`.
4. **Exporters** (M10) subscribe with their own cursor and buffer; a slow SIEM cannot slow the writer.
5. The **live tail** (`/events/stream`) subscribes with a small buffer and drops for slow clients.

## CEF mapping (M10)

`CEF:0|Sherlock|Sherlock WAF|<version>|<primary rule_id>|<primary message>|<severity 0-10>|src=<client.ip> requestMethod=<method> request=<host+path> act=<action> cs1Label=site cs1=<site_id> cs2Label=event_id cs2=<id> cn1Label=anomaly_score cn1=<inbound>`
