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

## Security testing gates

- Every milestone: `govulncheck`, `gosec` (via golangci-lint), CodeQL, dependency review, unit tests for any mitigation listed above.
- M2 onward: nuclei and ZAP baseline against Juice Shop behind Sherlock, nightly.
- M7: internal review of the admin surface against OWASP ASVS 5.0 L2 checklist.
- Before v1.0 (M11): external penetration test of admin surface and bypass testing of the data plane. Fix all critical and high findings before release.
