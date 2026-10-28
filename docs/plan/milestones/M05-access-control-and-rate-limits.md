# M5 · Access control and rate limits

- Phase: 2 · MVP
- Depends on: M3 (API), M4 (UI shell)
- Ships: `v0.3.0`
- Read first: `docs/architecture/request-pipeline.md`, `docs/architecture/config-model.md` (acl, rate_limits, auto_ban), `docs/security/threat-model.md` T4, T13

## Goal

Cheap, fast checks before the WAF: allow/deny lists, geo, reputation, rate limits and automatic bans, all manageable in the dashboard.

## Tasks

- [ ] **M5-T1** `internal/policy/ipset`: fast CIDR set (radix/patricia) for IPv4/IPv6 with benchmarks.
- [ ] **M5-T2** `sherlock_acl` module: allow lists (skip rate limit and bot), deny lists, country allow/deny, reputation threshold, temporary bans, password gate (bcrypt/argon2 hash, 401 with `WWW-Authenticate`).
- [ ] **M5-T3** Feeds job (`internal/controlplane/feeds`): GeoIP DB (DB-IP Lite default; MaxMind with licence key optional) download when `auto_update` is on, else manual upload; reputation lists (FireHOL level1, Spamhaus DROP); atomic swap into the data plane; SSRF-safe outbound client (`internal/netx`).
- [ ] **M5-T4** CrowdSec bouncer: poll LAPI decisions stream, apply as bans with source `crowdsec`.
- [ ] **M5-T5** `internal/policy/ratelimit`: sliding-window counter (two-bucket approximation), sharded map, memory cap with LRU eviction, `RateLimitBackend` interface (extension point).
- [ ] **M5-T6** `sherlock_ratelimit` module: rules by path glob, method, key (ip, header), actions block (429 + `Retry-After`), challenge (hands to bot module, effective from M6), log.
- [ ] **M5-T7** Auto-ban: count blocks per IP per site in window → ban; bans table and in-memory set; API `GET/POST/DELETE /bans`.
- [ ] **M5-T8** API + UI: IP lists page, site ACL tab, rate limits tab, bans page with unban.
- [ ] **M5-T8b** Global ACL lists and global rate limits applied to all sites through `global.defaults`, with per-site/endpoint `opt_out` (FR-POL-5), audited.
- [ ] **M5-T9** Tests: unit, benchmarks (ACL check < 1 µs p99 for 100k CIDRs), e2e (ban after repeated attacks).

## Acceptance criteria

1. 100,000-entry deny list adds < 0.1 ms p99 per request (benchmark).
2. Rate limit of 10/min on a path returns 429 on the 11th request within a minute and resets correctly; verified with k6.
3. Feeds update without restart and without dropped requests; a failed download keeps the previous data and raises a dashboard warning.
4. Allow-listed IP is still inspected by the WAF unless explicitly configured otherwise.
5. Feed and CrowdSec URLs pointing to 169.254.169.254 or 127.0.0.1 are refused unless explicitly allowed.
