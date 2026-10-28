# M6 · Bot defence

- Phase: 2 · MVP
- Depends on: M5
- Ships: `v0.4.0`
- Read first: `docs/architecture/config-model.md` (bot), `docs/architecture/request-pipeline.md`, `docs/security/threat-model.md` T16

## Goal

Stop automated abuse on browser-facing paths without hurting real users or API clients.

## Tasks

- [ ] **M6-T1** Clearance token: `HMAC-SHA256(key, ip_prefix|ua_hash|site|expiry)`, key rotation every 24 h with previous key accepted, constant-time verification; cookie `__sherlock_clearance` (`Secure`, `HttpOnly`, `SameSite=Lax`, 30 min default).
- [ ] **M6-T2** Proof-of-work challenge page: small self-contained JS (no external scripts, CSP nonce), SHA-256 PoW with configurable difficulty, `<noscript>` explanation, accessible text, posts solution to `/.sherlock/challenge/verify`, redirects back to the original URL (same-origin only).
- [ ] **M6-T3** Turnstile and hCaptcha options (site key/secret stored as secrets; server-side verification via SSRF-safe client).
- [ ] **M6-T4** Verified bots: user-agent claims for major search engines verified by reverse DNS + forward confirmation, cached 24 h; action allow/challenge/block.
- [ ] **M6-T5** `sherlock_bot` module: rules by path, country, reputation, and handoff from rate-limit `challenge` action; never challenge requests whose `Accept` does not include `text/html` (return 403 JSON with event ID instead); never challenge allow-listed IPs.
- [ ] **M6-T6** UI: site Bot tab; challenge pass/fail counts on overview.
- [ ] **M6-T7** Tests: token forgery and replay tests, Playwright test solving the PoW in a real browser, curl without JS gets challenged on protected paths.

## Acceptance criteria

1. A real browser passes the challenge in < 2 s at default difficulty on a mid-range laptop (measured in Playwright).
2. `curl` and headless clients without JS cannot obtain clearance; a cookie copied to another IP prefix is rejected.
3. Googlebot UA from a non-Google IP is treated as unverified.
4. API paths never receive HTML challenges.
5. Challenge page passes axe and works with keyboard and screen reader (announces progress).
