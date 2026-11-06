# Failure modes

What Sherlock does, and what you should expect to see, when a dependency fails. It is written from the code as of this release; where behaviour is not verified or not defined it is listed under [Known gaps](#known-gaps) instead of described. Chaos tests (`internal/app/chaos_test.go`, run nightly) check the rows marked *tested* below: each row names the observable signal, and the page is corrected where a test showed the code behaves differently. [What the tests do not cover](#covered-by-chaos-tests) is listed at the end.

Design rules that explain most rows: the data plane never waits for the event bus, the database or an exporter; every queue is bounded and loses its **oldest** entries first, and every loss is counted; configuration changes either fully apply or leave the previous configuration running ([requirements NFR-4 and NFR-5](../product/requirements.md)).

## Summary

| Failure | Traffic | What is lost | Signal |
| --- | --- | --- | --- |
| Upstream down or slow | 502, 503 or 504 from the proxy | Nothing | `sherlock_upstream_healthy` = 0, alert `upstream_unhealthy` |
| Database unavailable | Keeps flowing with the active configuration | Events beyond a small backlog; control-plane changes are refused | `/readyz` 503, writer errors in the log |
| Disk full | Keeps flowing | Event rows and exporter spool records | Log errors, `sherlock_exporter_dropped_total` |
| Event bus overloaded | Keeps flowing | Oldest events, counted | `sherlock_events_dropped_total` |
| Exporter destination down | Keeps flowing | Nothing until its spool is full | `sherlock_exporter_pending`, `_send_failures_total` |
| Configuration apply fails | Previous configuration keeps serving | Nothing | 4xx from the API, `config.apply` failure in the audit log; `/readyz` 503 only if the restore also fails |
| Admin listener unreachable | Keeps flowing | Metrics and health checks | Scrape failures |
| WAF engine error or panic | Per `fail_mode` (see below) | Nothing | `sherlock_internal_errors_total`, `core` finding in the event |

## Upstream is down or slow

- Sherlock does not retry or queue requests. The reverse proxy (Caddy) answers the client: a refused connection is a 502 (*tested*: the answer arrives at once, not after a timeout), a request with no usable upstream is a 503, and a dial, read or write timeout is a 504. Timeouts default to dial 5 s, read 60 s and write 60 s (`upstreams.timeouts`). These status codes are Caddy's; Sherlock does not rewrite them.
- Active health checking is off unless `upstreams.health_check.path` is set. Sherlock additionally probes every origin every 15 s (at most eight at once, per-probe timeout `upstreams.health_check.timeout`, default 2 s) for the metric only; a probe does not change routing.
- The WAF and the other modules still run before the proxy, so attacks are still blocked while the origin is down, and other sites on the node are unaffected (*tested*). When the origin returns, the site recovers without a reload and without leaking goroutines or descriptors (*tested*).
- Signals: `sherlock_upstream_healthy{site,upstream}` (0 when the last probe failed), alert rule `upstream_unhealthy`. A 5xx from the origin is not a security finding, so it creates no event.

## Database is unavailable

Applies to SQLite (locked, corrupted, volume lost) and PostgreSQL (down, network).

- **Data plane**: unaffected. It runs from the configuration activated in memory (NFR-4); requests are still inspected and blocked.
- **Event store**: the batch writer retries every second. While it is failing it keeps at most 4,000 events (8 batches of 500) and drops the oldest beyond that, logging `event store unavailable; dropping the oldest events` and counting them in the writer's own counter. The bus ring (65,536 events) overwrites unread events beyond that.
- **Exporters** read the bus and their own spool, not the database, so they keep delivering.
- **SQLite lock contention** waits up to 5 s (`busy_timeout`) before a statement fails. Store transactions take the write lock when they begin, so while another process holds the database lock even a read through the store waits and then fails; a plain read-only connection still reads (*tested*). `Ping` does not need the lock, so a locked database is not reported as unavailable by readiness.
- With the database locked, requests are not delayed, the writer fails and retries, events beyond the backlog cap are dropped oldest-first and counted, and when the lock is released the surviving backlog is written without a restart (*tested*).
- **Control plane**: changes that must be audited run in one transaction with their audit row, so while the database is down they fail and nothing changes. Sign-in and session checks need the database.
- **Readiness**: `GET /readyz` on the control-plane listener answers 503 `database unavailable`; `/healthz` stays 200.
- Recovery needs no action: the writer resumes and the backlog that survived is written.

## Disk is full

| Component | Behaviour |
| --- | --- |
| SQLite database (events, audit, configuration) | Writes fail as in "database unavailable". The audit row and the change share a transaction, so a change that cannot be audited is refused |
| Exporter spool | An append that fails is counted as a discarded record and the error is shown as the exporter's last error; a spool at its cap drops the oldest segment first (`sherlock_exporter_dropped_total{reason="spool_full"}`). Each spool is capped by `spool_max_mb` (default 256 MiB), so the spools together are bounded by the sum of their caps |
| Event file (`events.jsonl`, `access.jsonl`) | A failed write or rotation is logged as `event sink failed` and never delays a request; the independent stdout sink keeps receiving every event (*tested*). A failed **rotation** is logged (`event file rotation failed`) and the sink keeps appending to the current file, retrying the rotation once a minute (*tested*) |
| Request path | Not affected by the event and audit writes: no request waits for them. A WAF request body over `memory_limit` spills to the temporary directory; what happens when that write fails is not specified (see Known gaps) |
| Logs to stdout | Not affected |

There is no disk-space metric or alert in Sherlock; monitor the data directory volume yourself.

## Event bus is overloaded

`Publish` never blocks. When the ring (default 65,536 events) is full the oldest event is overwritten; if any subscriber had not read it, `sherlock_events_dropped_total` increases (*tested*: a flood of three times the ring against a subscriber that never reads, with requests unaffected). Rollup counters are updated at publish, so charts stay correct even for dropped events. A slow exporter loses only its own backlog (`sherlock_exporter_dropped_total{reason="lagged"}`). The live tail drops for slow clients. Alert rule `events_dropped` watches the counter.

## Exporter destination is down

Delivery is retried with exponential backoff and jitter from 1 s to 60 s; the spool absorbs the outage and delivery is at-least-once, so receivers must deduplicate on the record `id`. A permanent rejection (HTTP 4xx and similar) discards that batch and counts it (`reason="rejected"`). Other exporters and the data plane are not affected. Signals: `sherlock_exporter_pending`, `_spool_bytes` against `_spool_max_bytes`, `_send_failures_total`, `_last_success_timestamp_seconds`, and the exporter's last error in the API and dashboard.

## A configuration apply fails

| Stage | Result |
| --- | --- |
| Stale or missing `If-Match` | 412 or 428; nothing changes |
| Validation | 422 with every error; nothing changes; recorded in the audit log |
| Data plane rejects the configuration (`activation_failed`, 422) | The previous configuration stays live; recorded in the audit log |
| Activated, but saving the new version fails | The previous configuration is put back; if that also fails the node reports `/readyz` 503 `configuration could not be activated` because it is running something that was not saved |
| Stored configuration cannot be activated at start | The control plane starts in degraded mode so an operator can fix or roll back; `/readyz` answers 503 |

Rolling back is a normal change (`POST /api/v1/config/versions/{id}/rollback`). Changing the admin listener address binds the new address first, so a bind failure rejects the change and the old listener keeps serving.

## Admin listener is unreachable

The admin listener (`/metrics`, `/healthz`, `/readyz`) is separate from proxied traffic and from the control plane. If it is down or filtered (`global.admin.allowed_cidrs` answers 403 to others), traffic is unaffected; only monitoring is blind. Alert on scrape failure.

## The WAF engine errors or panics

| Where | `fail_mode: closed` (default for `block`) | `fail_mode: open` (default for `detect`) |
| --- | --- | --- |
| Inspection error or a panic inside WAF inspection (*tested*) | 503 block page, event with a `core` finding (`waf internal error: panic: ...`), the event id in the response header matches the stored event | Request proxied without inspection, event with the same `core` finding |
| Response inspection error (outbound inspection) | Response replaced by the block page | Response passed |
| Setup failure in `sherlock_core` (client address or event id) | 503 block page, no event (no decision exists), logged | Request proxied; later modules treat the missing decision as not inspectable |
| Panic elsewhere in the chain (another module, the proxy) | 503 block page if nothing was sent yet | **Same: 503 if nothing was sent yet.** `sherlock_core` recovers it after the request body may already have been consumed, so the request cannot be proxied safely; `fail_mode` is not consulted (unit-tested in `internal/dataplane/core`) |

Every case increments `sherlock_internal_errors_total` and is logged with the event id. If a response had already started, it is not rewritten.

## Known gaps

These are behaviours the code does not define, document or expose. They are open items, not promises.

1. **A panic outside WAF inspection is not subject to `fail_mode`.** This is how the code works and the pipeline document now says so; whether `fail_mode: open` should proxy such requests is a product decision, because the body may be consumed by then.
2. **The event writer's drop counter is not a metric.** Events dropped because the database stayed unavailable are logged and counted inside the writer, but only `sherlock_events_dropped_total` (bus overwrites) is exported.
3. **No disk-space signal.** Nothing alerts before the data volume fills.
4. **Boot without a usable database.** Starting while the database is unreachable is not documented; this page does not claim the process starts or refuses.
5. **Control-plane responses during a database outage** (status code and body of sign-in and API calls) are not specified.
6. **Data plane when the stored configuration cannot be activated at start.** The control plane stays up in degraded mode; which listeners the data plane serves in that state is not specified.
7. **Ban and rate-limit state** are in memory and persisted by a background job; what is lost when the database is down is not specified.
8. **No per-status upstream error metric.** `sherlock_requests_total` is labelled by site and action, so a rise in 502 or 504 is visible only through the upstream health metric, the access log or the origin.
9. **Request body spill failure.** A full or unwritable temporary directory while the WAF buffers a large body has no documented or tested fail-mode outcome.
10. **Retry of requests to a failed upstream** is Caddy's default behaviour (none configured by Sherlock); load-balancer retry settings are not exposed.
11. *(Closed.)* The event file sink used to keep a closed handle after a failed rotation and fail every later write until restart. It now reopens the current file, keeps appending and retries the rotation after a minute.

## Covered by chaos tests

`go test -race -tags 'chaos sherlock_testhooks' -run Chaos ./internal/app` (nightly workflow, job `chaos`):

| Test | Scenario |
| --- | --- |
| `TestChaosUpstreamOutage` | Origin killed and restarted: 502 at once, attacks still blocked, other sites unaffected, recovery without reload, no leaks, no internal errors |
| `TestChaosEventFileSinkFailure` | Event file cannot rotate: logged, requests unaffected, stdout sink complete, file sink recovers once the obstruction is removed |
| `TestChaosEventStoreLocked` | Database locked past the busy timeout: requests unaffected, writer fails and retries, backlog capped and counted, recovery after release |
| `TestChaosEventBusOverload` | Event flood against a stalled subscriber: no request delay, drops counted in `sherlock_events_dropped_total` |
| `TestChaosWAFPanicFollowsFailMode` | Forced WAF panic: `fail_mode` closed gives 503, open proxies; `core` finding, internal error counter, node stays healthy |

Not covered, because they need the whole node (`internal/server`) or a real outage and are therefore still described from the code only: the `/readyz` 503 for an unreachable database, control-plane answers during an outage (gap 5), starting without a usable database (gap 4), a full disk (the tests fail the rotation, not the allocation), the exporter spool on a full disk, and a panic outside WAF inspection (covered by a unit test only).
