# Request pipeline

Every site compiles to one Caddy route. The handler order is fixed by the compiler and MUST NOT be user-configurable.

| Order | Caddy handler (module ID) | Package | Purpose | Can terminate with |
| --- | --- | --- | --- | --- |
| 1 | `sherlock_core` | `internal/dataplane/core` | Resolves client IP, creates the request's `Decision` record, assigns an event ID, wraps the rest of the chain, emits the event at the end | 500 (internal error only) |
| 2 | `sherlock_acl` | `internal/dataplane/acl` | Allow/deny lists, geo, IP reputation, temporary bans, site password gate | 403, 401 |
| 3 | `sherlock_ratelimit` | `internal/dataplane/ratelimit` | Rate-limit rules and auto-ban counters | 429, or hands off to bot challenge |
| 4 | `sherlock_bot` | `internal/dataplane/bot` | Clearance cookie check, challenge page, good-bot verification | 403, challenge page (200 HTML) |
| 5 | `sherlock_api` | `internal/dataplane/apiguard` | OpenAPI validation, JWT validation, mTLS requirement | 400, 401, 403 |
| 6 | `sherlock_login` | `internal/dataplane/login` | Credential-stuffing protection on declared login paths (reads upstream response status) | 403, challenge |
| 6b | `sherlock_vpatch` | `internal/dataplane/waf` | Virtual-patch rules run as an extra rule set loaded into the same Coraza instance before CRS (phase 1–2), so they share one transaction | 403 block page |
| 7 | `sherlock_waf` | `internal/dataplane/waf` | Coraza transaction: phases 1 and 2 before proxying, phases 3 and 4 on the response if outbound inspection is on | 403 block page |
| 8 | `sherlock_dlp` | `internal/dataplane/dlp` | Response masking of card numbers and custom patterns | 502 if configured to block leaks |
| 9 | `reverse_proxy` | Caddy standard | Upstreams, load balancing, health checks, upstream TLS | Caddy's own 502/504 |

Each site route contains one subroute per endpoint (see config-model.md, "Policy inheritance"), ordered by match precedence, plus a site-default subroute. Every subroute carries the same handler chain configured with that endpoint's **effective** policy, resolved at compile time.

Handlers 6 and 8 are only compiled into the route when the site enables those features, so a site that does not use them pays no cost.

## Decision record

`sherlock_core` stores a `*policy.Decision` in the request context (Caddy `caddyhttp.VarsCtxKey` is not used for this; a typed context key is). Each later module appends `Finding`s:

```go
type Finding struct {
    Module   string   // "waf", "acl", "ratelimit", ...
    RuleID   string   // CRS rule ID, rate-limit rule name, list name
    Tags     []string // CRS tags, e.g. "attack-sqli", "paranoia-level/1"
    Severity Severity // info, notice, warning, error, critical
    Target   string   // e.g. "ARGS:id", "REQUEST_HEADERS:User-Agent"
    Matched  string   // matched data, truncated to 256 bytes and redacted (see events.md)
    Message  string
    Score    int      // anomaly score contribution, CRS only
}

type Decision struct {
    EventID   string     // ULID
    Action    Action     // allow, log, challenge, block, ratelimit, ban
    Mode      Mode       // site mode at time of request: off, detect, block
    Findings  []Finding
    Terminated string    // module that ended the request, empty if proxied
}
```

## Mode semantics

| Site mode | Behaviour |
| --- | --- |
| `off` | Only `sherlock_core` and `reverse_proxy` run. ACL deny lists still apply (they are a security control the user set explicitly). |
| `detect` | All modules run and record findings, but only ACL deny, rate-limit and bot challenge act. WAF, API, login and DLP findings are logged with `action=log` and the request is proxied. The dashboard calls these "would have blocked". |
| `block` | All modules act. |

Each module also has its own enable switch inside the site config, so a user can, for example, block on WAF but only log API schema violations.

## Client IP

1. If the TCP peer is in `trusted_proxies`, take the right-most untrusted address from `X-Forwarded-For` (or the configured header, e.g. `CF-Connecting-IP`).
2. Otherwise use the TCP peer address.

Use Caddy's `trusted_proxies` and `client_ip_headers` server options so Caddy's `{client_ip}` placeholder and Sherlock agree. All modules MUST read the IP from the decision record, never from headers directly.

## Coraza integration

- Sherlock implements its **own** Caddy handler around `github.com/corazawaf/coraza/v3` instead of using `coraza-caddy` directly, because it needs: per-site WAF instances compiled from Sherlock config, findings captured into the decision record via `WithErrorCallback` and transaction inspection, detect-mode handling, custom block pages with event IDs, and body-size limits per site. `coraza-caddy` (Apache-2.0) is the reference implementation; credit it in `NOTICE`.
- CRS files come from `github.com/corazawaf/coraza-coreruleset` (embedded `fs.FS`), pinned to a CRS release. Sherlock's base directives (`crs-setup` equivalent) are generated by the compiler from site settings.
- One `coraza.WAF` instance per site per config version, built at provision time. Transactions are created per request and always closed (`tx.Close()`), with `ProcessLogging()` called before close.
- Request bodies: Coraza buffers up to the site's `max_body_bytes` (default 10 MiB) in memory, spilling to a temp dir beyond `memory_limit` (default 128 KiB). Bodies over the limit: `block` returns 413, `detect` logs and proxies with inspection of the first part only (`SecRequestBodyLimitAction ProcessPartial`).
- Static assets: site option `skip_inspection_extensions` (default `.css .js .png .jpg .jpeg .gif .svg .ico .woff .woff2`) skips inspection for GET/HEAD requests **without a query string** only. Phase 2 is also where CRS inspects arguments, so skipping on the extension alone would let `/app.php/x.css?id=...` through.
- Detect mode runs Coraza with `SecRuleEngine DetectionOnly`: every rule is evaluated and recorded, nothing interrupts, and a match of CRS rule 949110 (inbound anomaly evaluation) is the "would have blocked" signal.
- Only the `REQUEST-*` CRS files are loaded until response inspection exists. CRS housekeeping rules (no severity) are not recorded as findings.
- Generated directives set `tx.allowed_methods` to `GET HEAD POST OPTIONS PUT PATCH DELETE` (CRS defaults to the first three, which blocks REST APIs); `TRACE` and `CONNECT` stay blocked.

## Fail mode (NFR-5)

If a module panics or Coraza returns an internal error:

- `sherlock_core` recovers the panic, records a `Finding{Module:"core", Severity: error}` and increments `sherlock_internal_errors_total`.
- Site `fail_mode: closed` (default for `block`) returns 503 with the block page. `fail_mode: open` (default for `detect`) proxies the request.

## Block and challenge responses

- Content negotiation: `Accept: text/html` gets the HTML page; anything else gets `application/problem+json` (RFC 9457) with `event_id`.
- Header `X-Sherlock-Event-Id` on every terminated response.
- Pages are Go `html/template` files embedded in the binary, overridable per site (upload in M4).
- Never echo request data into block pages.

## Performance rules for module authors

- No allocation-heavy work before cheap checks: ACL and rate limits run before Coraza for this reason.
- No network calls on the request path. Reputation lists, GeoIP, JWKS and CrowdSec decisions are refreshed by background jobs into in-memory structures swapped atomically (`atomic.Pointer`).
- No locks held across I/O. Rate-limit counters use sharded maps.
- Every module has a Go benchmark (`BenchmarkXxx`) run in CI; regressions over 10% fail the build (see [../engineering/testing-strategy.md](../engineering/testing-strategy.md)).
