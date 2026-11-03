# Threat model (Sherlock itself)

A WAF sits in front of financial applications and sees every request, including credentials and card data. Compromising Sherlock is worth more to an attacker than compromising one app behind it. This model covers Sherlock's own attack surface. Review it at every milestone that touches an item listed under "Applies to".

## Assets

| Asset | Why it matters |
| --- | --- |
| Proxied traffic (requests, responses, cookies, credentials) | Confidentiality of customers' users |
| TLS private keys (ACME and uploaded) | Impersonation of protected sites |
| Admin accounts, sessions, API tokens | Full control: disable protection, add exfiltration rules |
| Configuration and rules | Silent weakening of protection |
| Event store | Contains client IPs and redacted request excerpts (personal data) |
| Node key (`data/node.key`) | Decrypts stored secrets |
| Update channel | Code execution on every node |

## Trust boundaries

1. Internet → data-plane listeners (80/443)
2. Admin network → control-plane listener (9443)
3. Sherlock → upstream apps
4. Sherlock → external services (ACME CA, feeds, SIEM, update metadata)
5. Local OS user → data directory

## STRIDE

| # | Threat | Boundary | Mitigation | Applies to |
| --- | --- | --- | --- | --- |
| T1 | Request smuggling / desync between Sherlock and upstream | 1, 3 | Rely on Caddy's HTTP parsing; normalise and re-serialise requests to upstream; reject ambiguous `Content-Length`/`Transfer-Encoding`; include smuggling cases in nuclei suite | M1, M2 |
| T2 | WAF bypass via parser differences (encoding, multipart, JSON) | 1 | CRS + Coraza body processors; go-ftw regression; track Coraza CVEs (several in 2026); fuzz body processors | M1, M8 |
| T3 | ReDoS or CPU exhaustion through crafted input | 1 | Coraza uses Go RE2 (linear time); body size limits; per-request inspection time budget metric; fuzzing | M1, M2 |
| T4 | Memory exhaustion via large bodies or many connections | 1 | Body limits with disk spill, Caddy timeouts and max header sizes, rate limits before WAF | M1, M5 |
| T5 | Brute force or credential stuffing on admin login | 2 | Mandatory MFA for admins, login rate limits, lockout with exponential backoff, admin listener restricted by CIDR | M3 |
| T6 | Session hijacking, CSRF, XSS in dashboard | 2 | HttpOnly/Secure/SameSite=Strict cookies, CSRF tokens, strict CSP (`default-src 'self'`), Vue auto-escaping, no `v-html` with event data (lint rule) | M3, M4, M7 |
| T7 | Stored XSS via attack payloads shown in the attack explorer | 1→2 | Event data rendered as text only; matched data shown in `<code>` with escaping; Playwright test injects XSS payloads into events | M7 |
| T8 | Privilege escalation (viewer → admin), IDOR | 2 | Central permission middleware generated from the OpenAPI spec; tests for every route × role | M3 |
| T9 | Malicious custom SecLang rule exfiltrating data or executing commands | 2 | Disallow `exec`, `SecRuleScript` Lua, `SecAuditLog` directives in user rules; validator with allow-list of actions; admins only | M8 |
| T10 | Tampering with config or audit logs | 2, 5 | Every change audited with actor; hash-chained audit rows (Enterprise adds signing and WORM) | M3 |
| T11 | Secrets at rest disclosed | 5 | Secrets encrypted with node key; data dir 0700; key separate from backups by default | M3, M7 |
| T12 | Malicious update / supply-chain compromise | 4 | release manifest signed with an Ed25519 key embedded in the binary, verified offline by `sherlock update` with checksums, downgrade refusal and a re-verifying root apply step ([ADR-0017](../architecture/adr/0017-update-verification.md)); cosign signatures in CI as an extra; SBOM; pinned dependencies with Renovate; `govulncheck` in CI | M0, M7 |
| T13 | SSRF via user-configured URLs (JWKS, webhooks, feeds) | 2→4 | Outbound HTTP client with deny-list for link-local, metadata IPs (169.254.169.254), loopback, unless explicitly allowed; timeouts. JWKS URLs must be https, literal internal addresses are refused at config validation and the dialled address is checked again after DNS resolution (`internal/netx`), so rebinding and redirects cannot reach an internal service; the fetch runs in a background job, never on the request path ([ADR-0018](../architecture/adr/0018-api-protection.md)) | M9, M10 |
| T14 | Sensitive data in Sherlock's logs and events | 1 | Redaction rules (events.md); no request bodies by default; PAN masking | M2, M11 |
| T15 | Denial of service of the admin plane affecting traffic | 2 | Separate listener and goroutine pools; data plane independent of control plane (NFR-4) | M3 |
| T16 | Clearance-cookie forgery or replay for bot challenge | 1 | HMAC-SHA256 with rotating key, bound to IP prefix + UA hash + expiry; constant-time compare | M6 |
| T17 | Open redirect / host header attacks | 1 | Only configured hosts are served; unknown hosts get a static 421/404 without upstream contact | M1 |
| T18 | SSRF through exporter and notification-channel URLs: an admin (or a stolen admin session) points an exporter at the cloud metadata service or an internal admin interface | 4 | The webhook, OTLP and channel senders use the `internal/netx` client: link-local (including 169.254.169.254) and unspecified addresses are refused at connect time after DNS resolution, so rebinding does not help; redirects are never followed; HTTPS required unless `allow_http`; URLs with embedded credentials are rejected; response bodies are size-limited. Syslog destinations are plain host:port and go through the same dialer rule. Loopback and private ranges are deliberately allowed (SIEMs are internal), so an admin can still make Sherlock send signed batches to an internal service. Residual: that needs the `config:write` permission and is audited | M10 |
| T19 | Exposure of exporter and channel secrets (HMAC keys, webhook URLs, SMTP passwords, bearer tokens) through the API, the audit log, logs, errors or backups | 2, 5 | Settings are one XChaCha20-Poly1305 secret per object; the API masks credential-looking values (`********`) and a mask sent back keeps the stored value; the audit log records type, stream and enabled only; sender errors name the host, never the URL, header values or secret; the node key stays out of backups by default. Residual: the masking is key-name based, so an extension type that stores a secret under an unusual key name could show it; mask patterns are reviewed per type, and viewers can read masked settings | M10 |
| T20 | Header, address and markup injection through alert text or exported records (attacker-controlled strings in paths, hosts, countries) | 1→4 | Alert messages carry only ids, counts, site, country code and host; control characters are stripped and lengths bounded; Slack and Teams markup is escaped; SMTP rejects CR/LF in addresses and subjects; CEF escaping of `\`, `|`, `=` and line breaks; syslog payload line breaks replaced; JSON encoded by the standard library. Residual: a receiver that renders exported fields as HTML or SQL is the receiver's responsibility | M10 |
| T21 | Spool on disk: data exposure or disk exhaustion by a dead destination | 5 | Spool directories are mode 0700 and files 0600 under the data directory, inside the same trust boundary as the event store; each spool is capped at 256 MiB with drop-oldest and an alertable `dropped{reason="spool_full"}` counter, so total spool disk use is bounded by `exporters × 256 MiB`; records are CRC-checked and a torn tail is repaired at start. Residual: the spool is not encrypted at rest (events are already redacted before they leave the request path); use disk encryption where required. The spool size is not yet configurable | M10 |
| T22 | Alert flooding or alert suppression: an attacker causes thousands of notifications, or an alert is silenced | 1→4 | Per-subject cool-down (60 s to 7 days), at most 25 notifications per rule per evaluation, at most 10,000 tracked subjects, 16 concurrent sends with a 15 s timeout, and failing channels never block other rules. Suppression is visible (a suppressed counter and last-notify error in the dashboard). Residual: alert state is in memory, so a restart repeats still-true alerts once; a long cool-down hides a second incident on the same subject | M10 |
| T23 | Webhook replay or forgery: a captured exporter request is replayed, or a third party posts fake records to the receiver | 4 | Each request is signed with HMAC-SHA256 over `<timestamp>.<body>` using a secret of at least 32 bytes; receivers reject timestamps outside a window (5 minutes recommended), compare in constant time and deduplicate on record ids ([webhook-signature.md](../integrations/webhook-signature.md)). Residual: replay inside the window is possible unless the receiver remembers seen ids; the secret is shared, so a receiver compromise allows forging | M10 |

## Security testing gates

- Every milestone: `govulncheck`, `gosec` (via golangci-lint), dependency review, unit tests for any mitigation listed above.
- M2 onward: nuclei and ZAP baseline against Juice Shop behind Sherlock, nightly.
- M7: internal review of the admin surface against OWASP ASVS 5.0 L2 checklist.
- Before v1.0 (M11): external penetration test of admin surface and bypass testing of the data plane. Fix all critical and high findings before release.
