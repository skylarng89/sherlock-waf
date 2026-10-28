# ADR-0003: Coraza v3 and OWASP CRS 4, own Caddy handler

- Status: Accepted
- Date: 2026-10-28

## Context

Detection quality is the core of a WAF. The OWASP CRS project recommends Coraza for new CRS 4 deployments. Coraza is a Go library implementing SecLang. `coraza-caddy` exists but gives limited control over event capture, per-site instances and block pages. Coraza had several CVEs in 2026 (parser and recursion issues), so we must track its releases.

## Decision

- Use `github.com/corazawaf/coraza/v3` directly inside our own `sherlock_waf` Caddy handler, using `coraza-caddy` as reference (Apache-2.0, credited in NOTICE).
- Embed CRS via `github.com/corazawaf/coraza-coreruleset` pinned to a CRS 4 release (4.30.0 at time of writing; 4.25.x is the LTS line).
- Generate the CRS setup directives from site config.
- Run the CRS regression suite with `go-ftw` against the built binary in CI.

## Consequences

- We inherit a decade of community rules and a test suite.
- We own the integration code (a few hundred lines) and must keep it in sync with Coraza API changes.
- No proprietary detection engine; differentiation comes from policy, UX, evidence and finance-specific modules.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Use `coraza-caddy` unmodified | No event capture into our decision record, no detect mode with "would block" semantics, no custom block page with event ID |
| Write our own semantic engine | Large research effort; revisit after v1.0 with real traffic |
