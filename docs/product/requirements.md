# Requirements (open-source core)

Each requirement has an ID that milestone tasks and tests reference. "M" is the milestone that delivers it (see [../plan/roadmap.md](../plan/roadmap.md)). Enterprise requirements live in the enterprise repository.

## Functional requirements

### Proxy and TLS (FR-PRX)

| ID | Requirement | M |
| --- | --- | --- |
| FR-PRX-1 | Sherlock MUST reverse-proxy HTTP/1.1, HTTP/2 and HTTP/3 traffic to one or more upstreams per site, with load balancing (round robin, least connections) and active health checks. | M1, M4 |
| FR-PRX-2 | Each site MUST be matched by one or more hostnames, with optional path prefixes. | M1 |
| FR-PRX-3 | Sherlock MUST obtain and renew certificates automatically via ACME (Let's Encrypt, ZeroSSL, or a custom ACME CA such as an internal step-ca) and MUST accept uploaded certificates. | M1, M4 |
| FR-PRX-4 | Sherlock MUST support TLS to upstreams, including upstream mTLS with a client certificate. | M4 |
| FR-PRX-5 | Sherlock MUST pass the real client IP to upstreams (`X-Forwarded-For`, `X-Real-IP`) and MUST support trusted-proxy configuration when itself behind a load balancer. | M1 |
| FR-PRX-6 | Sherlock MUST support WebSocket and gRPC proxying; WAF inspection applies to the handshake. | M4 |
| FR-PRX-7 | Sherlock SHOULD add hardening response headers per site (HSTS, X-Content-Type-Options, Referrer-Policy, optional CSP). | M4 |

### Attack detection (FR-WAF)

| ID | Requirement | M |
| --- | --- | --- |
| FR-WAF-1 | Sherlock MUST inspect requests with Coraza running the OWASP CRS 4 rule set embedded in the binary. | M1 |
| FR-WAF-2 | Each site MUST have a mode: `off`, `detect` (log only) or `block`. New sites default to `detect`. | M1 |
| FR-WAF-3 | Each site MUST allow setting CRS paranoia level (1 to 4), inbound and outbound anomaly thresholds. | M1 |
| FR-WAF-4 | Users MUST be able to create rule exclusions scoped to site, path, HTTP method, rule ID or tag, and request variable (e.g. `ARGS:password`). | M8 |
| FR-WAF-5 | Users MUST be able to create a rule exclusion directly from an event in the attack explorer. | M8 |
| FR-WAF-6 | Users MAY add custom SecLang rules per site, validated before saving. | M8 |
| FR-WAF-7 | Request body inspection MUST support URL-encoded, multipart, JSON and XML bodies, with a configurable size limit per site. | M1 |
| FR-WAF-8 | Response inspection (CRS outbound rules) MUST be optional per site and off by default. | M8 |
| FR-WAF-9 | Blocked requests MUST get a configurable block page (HTML for browsers, JSON for API clients) containing an event ID the user can quote to support. | M1, M4 |

### Policy hierarchy (FR-POL)

| ID | Requirement | M |
| --- | --- | --- |
| FR-POL-1 | Protection settings MUST be definable at three levels: **global defaults**, **site**, and **endpoint** (path pattern + optional methods within a site). A lower level overrides only the fields it sets; everything else is inherited. | M1 (model), M4 (UI) |
| FR-POL-2 | Overridable fields: mode, fail mode, WAF settings (enabled, paranoia levels, thresholds, body limit, outbound inspection, rule/tag disables), virtual patches, ACL, rate limits, bot, API checks, login protection, DLP, block page. | M1, then each feature's milestone |
| FR-POL-3 | Endpoint matching MUST be deterministic: exact path beats prefix/glob; longer pattern beats shorter; method-specific beats any-method; ties are a validation error. | M1 |
| FR-POL-4 | The API and dashboard MUST show the **effective policy** for any site and endpoint, with the source level of each value (global, site or endpoint), and MUST be able to test which endpoint a given method + path matches. | M3, M4 |
| FR-POL-5 | Global rate limits, ACL lists and virtual patches MAY be applied to all sites; sites can opt out of a specific global item only explicitly (recorded in audit). | M5, M8 |

### Virtual patching (FR-VP)

| ID | Requirement | M |
| --- | --- | --- |
| FR-VP-1 | Sherlock MUST ship a curated **virtual-patching rule pack**: SecLang rules targeting specific, actively exploited web-application CVEs not reliably blocked by CRS alone. Each rule carries its CVE ID(s), affected product, severity, references and a test. | M8 |
| FR-VP-2 | Selection policy: CVEs in the CISA Known Exploited Vulnerabilities catalogue (and other confirmed in-the-wild exploitation) that affect web-facing software commonly deployed by target users (CMS, e-commerce, VPN/gateway web portals, Java/PHP/.NET frameworks, API gateways, file-transfer apps). Documented in `docs/security/virtual-patching-process.md`. | M8 |
| FR-VP-3 | Virtual patches are enabled by default in `block` sites when they cannot match benign traffic for unaffected apps; product-specific ones may default to on only when the user declares the technology stack of the site ("This site runs: WordPress, Spring, …"). | M8 |
| FR-VP-4 | Users can enable/disable virtual patches globally, per site and per endpoint (FR-POL); the dashboard lists covered CVEs, hits per CVE and the rule-pack version. | M8 |
| FR-VP-5 | Each rule has a positive test (exploit request blocked, using a nuclei template or go-ftw case) and a negative test (benign corpus unaffected) in CI. | M8 |
| FR-VP-6 | Rule pack updates ship in Sherlock releases; for a newly exploited critical CVE the target is an emergency patch release within 24 hours of the rule being validated. | M8, ongoing |

### Access control and abuse (FR-ACL)

| ID | Requirement | M |
| --- | --- | --- |
| FR-ACL-1 | Allow and deny lists by IP and CIDR, globally and per site. Allow-listed clients skip rate limits and bot checks but not attack detection unless explicitly configured. | M5 |
| FR-ACL-2 | Country allow/deny using a local GeoIP database (MaxMind GeoLite2 or DB-IP Lite), updated by the user or by an opt-in job. | M5 |
| FR-ACL-3 | IP reputation from public blocklists (e.g. FireHOL level 1, Spamhaus DROP) and optional CrowdSec bouncer integration. | M5 |
| FR-ACL-4 | Rate limits per site with rules matching path pattern, method and key (IP, header, JWT claim, API key), using a sliding-window algorithm. Actions: block (429), challenge, log. | M5, M9 |
| FR-ACL-5 | Automatic temporary bans when a client triggers N blocks or N 4xx responses in a window. | M5 |
| FR-ACL-6 | Per-site HTTP basic or password gate in front of the site (for staging sites). | M5 |

### Bot defence (FR-BOT)

| ID | Requirement | M |
| --- | --- | --- |
| FR-BOT-1 | A JavaScript proof-of-work challenge issuing a signed, short-lived clearance cookie bound to client IP prefix and User-Agent. | M6 |
| FR-BOT-2 | Optional third-party captcha: Cloudflare Turnstile, hCaptcha. | M6 |
| FR-BOT-3 | Verified good bots (Googlebot, Bingbot, etc.) recognised by reverse-DNS verification and allowed. | M6 |
| FR-BOT-4 | Challenge rules per site by path, country, reputation score or rate-limit trigger. API paths MUST NOT get HTML challenges. | M6 |

### API protection (FR-API)

| ID | Requirement | M |
| --- | --- | --- |
| FR-API-1 | Upload an OpenAPI 3.0/3.1 document per site; requests not matching a documented path, method, parameter or JSON schema can be logged or blocked. | M9 |
| FR-API-2 | JWT validation (signature via JWKS URL or static key, `exp`, `nbf`, `iss`, `aud`) on chosen paths. | M9 |
| FR-API-3 | Rate limits keyed on JWT claim or API key header (FR-ACL-4). | M9 |
| FR-API-4 | mTLS client-certificate requirement per site or path (for open-banking style APIs). | M9 |

### Finance protections (FR-FIN)

| ID | Requirement | M |
| --- | --- | --- |
| FR-FIN-1 | Login endpoint protection: declare login paths and the username field; detect credential stuffing by failed-login velocity per IP, per username and per device fingerprint; respond with challenge or block. | M11 |
| FR-FIN-2 | Sensitive data masking: detect card numbers (PAN, Luhn-validated) and configurable patterns (national IDs, IBANs) in responses and mask or block; never write them to Sherlock's own logs. | M11 |
| FR-FIN-3 | Detect-only rollout report: for a site in detect mode, show what would have been blocked over a chosen period. | M7 |

### Events and export (FR-EVT)

| ID | Requirement | M |
| --- | --- | --- |
| FR-EVT-1 | Every security decision (block, challenge, log-only match, rate limit, ban) MUST produce a structured event as defined in [../architecture/events.md](../architecture/events.md). | M2 |
| FR-EVT-2 | Events MUST be stored locally with configurable retention (default 30 days). | M3 |
| FR-EVT-3 | Access logs (all requests) MUST be optional and sampled, separate from security events. | M2 |
| FR-EVT-4 | Export to syslog (RFC 5424, CEF format), JSON over HTTPS webhook, and OpenTelemetry logs. | M10 |
| FR-EVT-5 | Alert rules (e.g. more than N blocks in 5 minutes on a site) sending to email, webhook, Slack-compatible webhook. | M10 |
| FR-EVT-6 | Prometheus metrics endpoint for requests, decisions, latency, upstream health. | M2 |

### Control plane and dashboard (FR-CP)

| ID | Requirement | M |
| --- | --- | --- |
| FR-CP-1 | All configuration MUST be manageable via a versioned REST API (`/api/v1`). The dashboard uses only this public API. | M3 |
| FR-CP-2 | Configuration MUST be exportable and importable as a single YAML document, enabling GitOps. | M3 |
| FR-CP-3 | Every config change MUST be validated, compiled and applied atomically with zero dropped connections; a failed apply rolls back. | M3 |
| FR-CP-4 | Config history: every applied version stored with author, time and diff; rollback to any version. | M3 |
| FR-CP-5 | Local users with argon2id passwords, mandatory TOTP MFA for admins, session timeout, API tokens with scopes. | M3 |
| FR-CP-6 | Roles: Admin (all), Viewer (read-only). | M3 |
| FR-CP-7 | Audit log of logins and changes, viewable and exportable. | M3 |
| FR-CP-8 | Dashboard pages: overview, sites, site detail (settings, rules, exclusions, rate limits, bot, API), certificates, attack explorer, event detail, analytics, IP lists, users, audit log, system (updates, backups, health). | M4, M7 |
| FR-CP-9 | Setup wizard on first launch: create admin, enable MFA, add first site in detect mode. | M4 |

### Lifecycle (FR-LC)

| ID | Requirement | M |
| --- | --- | --- |
| FR-LC-1 | One-line installer for Debian/Ubuntu/RHEL family, plus Docker Compose and a container image. | M7 |
| FR-LC-2 | `sherlock update` checks signed release metadata and upgrades in place; offline bundle import for air-gapped hosts. | M7 |
| FR-LC-3 | Automatic backup of config DB before every migration and on schedule; `sherlock backup` / `sherlock restore`. | M7 |
| FR-LC-4 | Helm chart and Kubernetes deployment (Sherlock as a gateway in front of services). | M12 |

## Non-functional requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | **Latency**: p95 added latency ≤ 5 ms and p99 ≤ 15 ms for a 1 KB GET at paranoia level 1, 2 vCPU node, measured by the k6 benchmark in CI. Calibrated in M2; the budget may be revised once, by ADR. |
| NFR-2 | **Throughput**: ≥ 2,000 requests/s per 2 vCPU node at PL1 with a 1 KB GET mix. Calibrated in M2. |
| NFR-3 | **Memory**: idle node ≤ 150 MB RSS; ≤ 1 GB at NFR-2 load. |
| NFR-4 | **Availability of data plane**: control-plane failure or restart MUST NOT interrupt proxied traffic. |
| NFR-5 | **Fail mode**: per site, configurable fail-open or fail-closed if the WAF engine errors on a request; default fail-closed for `block` sites. |
| NFR-6 | **Security of Sherlock itself**: meets OWASP ASVS 5.0 Level 2 for the admin surface; admin UI/API can be bound to a separate interface/port from proxied traffic; no default credentials. |
| NFR-7 | **Supply chain**: reproducible builds, SBOM (SPDX) per release, signed artefacts (cosign), dependency vulnerability scanning in CI. |
| NFR-8 | **Offline**: all features work without internet access, except ACME, opt-in update checks and opt-in feed downloads. |
| NFR-9 | **Privacy**: no telemetry by default; opt-in anonymous usage stats only. Sensitive values (passwords, tokens, PANs) redacted from logs by default. |
| NFR-10 | **Portability**: Linux amd64 and arm64; single static binary; no CGO in the default build. |
| NFR-11 | **Accessibility**: dashboard meets WCAG 2.2 AA. |
| NFR-12 | **Upgrades**: in-place upgrade between any two consecutive minor versions without manual steps; config schema migrations automatic. |
| NFR-13 | **Observability**: structured JSON logs (`log/slog`), Prometheus metrics, health endpoints `/healthz` and `/readyz`. |
| NFR-14 | **Documentation**: every user-facing feature documented before its milestone closes. |
