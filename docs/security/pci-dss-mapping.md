# PCI DSS mapping guide (v4.0)

How Sherlock WAF helps a merchant or service provider meet the web-application and logging requirements of PCI DSS v4.0, what it leaves to you, and what evidence it produces.

**This is not legal advice and not QSA advice.** Sherlock is open-source software, not a PCI-certified product, and using it does not make an environment compliant. Whether a control satisfies a requirement is decided by your assessor for your environment. Check requirement wording and dates against the current PCI DSS text.

## Summary

| Requirement | What Sherlock provides | What you still do |
| --- | --- | --- |
| 6.4.2 Automated technical solution for public-facing web applications | Inline WAF (Coraza with OWASP CRS, virtual patches, API schema and JWT checks) that blocks in `block` mode and records every decision | Run in `block` mode, keep it updated, tune false positives, prove it is active |
| 6.4.1 (superseded by 6.4.2) | Same capability; the older "manual review or WAF" choice is no longer the current requirement | Confirm the applicable version and dates with your assessor |
| 10.2 Audit logs | Hash-chained audit log of control-plane actions; security events; optional sampled access log | Application and CDE access logs are yours; Sherlock is one source |
| 10.3 Protection of logs | Tamper-evident audit chain, restricted data directory, export to your SIEM | Central, access-controlled log storage; integrity monitoring there |
| 10.4 Log review | Alert rules and metrics that automate part of the review | Daily review process, SIEM correlation, follow-up |
| 10.5 Retention | Local event retention (default 30 days) and export | 12 months retention, 3 months immediately available, in your SIEM |
| 10.6 Time synchronisation | Timestamps come from the host clock | NTP or equivalent on every node |
| 10.7 Failure of critical controls | Metrics, `/readyz` and alert rules for dropped events, unhealthy upstreams, failed exporters | Wire them into paging and respond |
| 3.4, 3.5 Displaying and storing PAN | Optional masking of PANs in responses; PANs redacted from events and logs | Application-level masking and storage rules; Sherlock does not reduce scope |
| 8.x Authentication | Mandatory TOTP MFA, lockout, 12-character passwords with breach screening, single-use tokens | Policy settings that must match 8.3.4, 8.2.8; user lifecycle |
| 4.2 Transport security | TLS 1.2 or 1.3 listeners, ACME or uploaded certificates, HSTS, TLS to the origin | Cipher and protocol review, certificates inventory, TLS inside the CDE |

## 6.4.2: detect and prevent web-based attacks

**What Sherlock provides**

- A WAF in front of each site: Coraza with the OWASP Core Rule Set at the configured paranoia level ([request pipeline](../architecture/request-pipeline.md)), CVE virtual patches ([virtual patching](virtual-patching-process.md)), API protection (OpenAPI conformance, JWT, mTLS: [API protection](../user/api-protection.md)), and optional response inspection (`waf.outbound_inspection`).
- Prevention is per site and per endpoint through `policy.mode: block`. `detect` records what would have been blocked and does not prevent.
- `fail_mode: closed` makes a WAF engine error answer 503 instead of passing the request ([failure modes](../operations/failure-modes.md)). It is the default for `block` sites.
- Rule updates ship in releases; CRS security updates are targeted within 72 hours of the CRS release ([release process](../release/release-process.md)). Apply them with `sherlock update` or by redeploying the image.

**What you still do**

- Put every public-facing web application that is in scope behind a site in `block` mode, including APIs. A site left in `detect`, or an endpoint set to `waf.enabled: false`, is not covered.
- Roll out with the [detect-to-block guide](../user/detect-to-block.md), tune false positives, and review the would-block report after releases.
- Keep Sherlock and the CRS current, and record when you applied each update.
- Show that the solution is **actively running, generating audit logs, and cannot be bypassed or disabled by unauthorised users** (the wording of 6.4.2): keep the origin reachable only through Sherlock (network controls), and restrict `config:write` administrators.

**Evidence an assessor can collect**

- The effective policy of each site, with the source of every value: `GET /api/v1/sites/{site}/effective-policy`; configuration versions and diffs: `GET /api/v1/config/versions`.
- Security events with rule ids and actions (`sherlock.event.v1`, [event schema](../reference/event.schema.json)); metric `sherlock_requests_total{site,action}` showing `block` decisions.
- The audit log entries for every mode or policy change (`config.apply`), checked with `sherlock audit verify`.
- CI and nightly results for the rule regression suite are published with each release.

**Limits**

- A WAF in `detect` mode does not satisfy "prevent". Neither does a WAF that is bypassed by direct access to the origin.
- Sherlock does not replace secure development, vulnerability management (6.3.x) or penetration testing (11.4).

## 6.4.1

PCI DSS v4.0 6.4.1 allowed either manual application vulnerability assessments or a WAF for public-facing web applications until 6.4.2 took effect on 31 March 2025; 6.4.2 (above) is the requirement that now applies. If your assessor still uses 6.4.1 for any period, the same evidence as 6.4.2 applies. Sherlock does not perform vulnerability assessments of your application.

## 10.2, 10.3: audit logs and their protection

**What Sherlock provides**

- **Control-plane audit log.** Every change by a person, token or the system is a row with actor, source address, action, object and time, for example `config.apply`, `auth.login`, `auth.login_failed`, `auth.mfa_enrolled`, `user.password_changed`, `user.*`, `token.*` ([control plane](../user/control-plane.md)). Rows are append-only and **hash-chained**; `sherlock audit verify` detects edits, deletions and truncation. Credentials, tokens and codes are never recorded.
- **Security events.** One event per request that had at least one finding, plus system events, with time, node, site, client address, action, mode, status and findings ([events](../architecture/events.md)). Passwords, tokens, card numbers and cookies are redacted or never captured.
- **Access log (optional).** `global.events.access_log` records a sample of clean requests. It is sampled and is not a complete record of access.
- Export to syslog (CEF or JSON, UDP, TCP, TLS), HMAC-signed webhook, or OpenTelemetry, for the audit and the event stream ([exporters](../user/exporters-and-alerts.md)). Delivery is at-least-once from a disk spool, so a short SIEM outage loses nothing until the spool is full.
- The data directory is mode 0700 and secrets are encrypted at rest ([threat model](threat-model.md), T10 and T11).

**What you still do**

- Sherlock's events record requests that matched something. They do **not** show every individual access to cardholder data (10.2.1.1); that log comes from the application or the CDE systems. A full access log at the proxy requires `access_log` with `sample_rate` 1, which has storage and privacy costs.
- Send both streams to a central log server with role-based access, write-once or integrity-monitored storage, and alerting on changes (10.3.2 to 10.3.4). The audit chain is tamper-evident, not tamper-proof; signing and WORM storage are not in the open-source edition.
- Verify the chain on a schedule and keep the verification result.

**Evidence**: `sherlock audit verify` output, `GET /api/v1/audit` exports, exporter configuration (`GET /api/v1/exporters`, secrets masked) and the exporter metrics `sherlock_exporter_sent_total`, `sherlock_exporter_dropped_total`, `sherlock_exporter_last_success_timestamp_seconds`.

## 10.4: log review

**What Sherlock provides**: alert rules that notify by email, webhook, Slack-compatible webhook or Teams: block rate per site (`blocks_threshold`), traffic from a new country (`new_country`), expiring certificates, feed failures, dropped events and unhealthy upstreams. The dashboard events view and the would-block report support manual review.

**What you still do**: define the daily review (10.4.1) and the automated review mechanism (10.4.1.1) in your SIEM, review exceptions (10.4.2) and follow up. Sherlock's alerts are inputs, not a review process.

## 10.5: retention

Stored events default to 30 days (`global.events.retention_days`, control-plane database only). That is shorter than the 12 months PCI requires, with 3 months immediately available. Retention is the responsibility of your central log store: export both streams and configure retention there. The audit log is not trimmed by the event retention job; confirm your own retention policy for the Sherlock database and backups ([backup and restore](../user/backup-restore.md)).

## 10.6: time synchronisation

Sherlock stamps events and audit rows from the host clock. Run NTP or an equivalent on every node and review it as you do for other CDE systems. Sherlock does not synchronise time itself.

## 10.7: failures of critical security controls

**What Sherlock provides**

- Metrics: `sherlock_internal_errors_total` (recovered module failures), `sherlock_events_dropped_total`, `sherlock_exporter_*`, `sherlock_upstream_healthy`, `sherlock_cert_expiry_seconds`, `sherlock_config_version_info`.
- `GET /readyz` fails when the database is unreachable or the configuration could not be activated; `GET /healthz` is liveness.
- Alert rules `events_dropped` and `upstream_unhealthy`.
- Fail mode decides what a failed engine does to traffic (closed returns 503 for `block` sites).

**What you still do**: alert on `sherlock_internal_errors_total` increasing, on `/readyz`, on a stalled `sherlock_exporter_last_success_timestamp_seconds`, and on a node that stops reporting at all (a down node produces no alert of its own). Document the response and restoration process (10.7.2, 10.7.3). See [failure modes](../operations/failure-modes.md) for what to expect.

## 3.4, 3.5: displaying and storing PAN

**What Sherlock provides**

- Events and logs never keep a full PAN: query and body values that look like card numbers are replaced with the last four digits, parameters with names such as `card`, `pan`, `cvv` or `password` are redacted, and `Authorization` and `Cookie` headers are never captured. Request body excerpts are off by default.
- Data protection (`policy.dlp`, [data protection](../user/data-protection.md)) can mask PANs in responses to clients, keeping the last four digits, or block responses that contain them.

**Limits**

- DLP is defence in depth. It is pattern-based, scans only the configured content types up to a size limit, and cannot see data it cannot decode. Do not use it as the only control for 3.4.1 (masking when displayed) or 3.5.1 (rendering stored PAN unreadable); fix the application.
- Sherlock decrypts TLS and carries cardholder data in memory when it proxies card traffic. **It is therefore a system component in scope for the same traffic**, and masking responses does not change that. Check with your assessor how a proxy that terminates TLS is scoped in your design.
- Sherlock does not store PANs, but if you enable body excerpts or custom log fields you can cause PANs to be stored in events; do not.

## 8: authentication of control-plane users

| Requirement | Sherlock behaviour | Check |
| --- | --- | --- |
| 8.4.2 MFA for access into the CDE | TOTP two-step verification is mandatory for every dashboard user; codes are single-use; password change and enrolment need a code ([control plane](../user/control-plane.md)) | Confirm no account has MFA reset without a record (`user.*` audit rows) |
| 8.3.4 Lock out after no more than 10 failed attempts, for at least 30 minutes | Progressive lock after `SHERLOCK_LOGIN_LOCK_AFTER` consecutive failures (default 5), maximum lock `SHERLOCK_LOGIN_LOCK_MAX_MINUTES` | **Set the maximum lock to at least 30 minutes**; the default maximum is shorter than the requirement |
| 8.3.6 Minimum password length and complexity | At least 12 characters, screened against a corpus of breached passwords | Matches the 12-character minimum |
| 8.2.8 Re-authenticate after 15 minutes idle | Sessions end after 30 minutes without use | **Longer than 15 minutes and not configurable today**: record this gap or use a separate control |
| 8.2.1, 8.6 Unique IDs, service accounts | Named users and scoped API tokens with an expiry and a per-user limit | Review token scopes and CIDR limits; revoke unused tokens |

Sherlock does not integrate with your directory or SSO in the open-source edition.

## 4.2: strong cryptography in transit

**What Sherlock provides**: TLS 1.2 or 1.3 on listeners (`tls.min_version`, default 1.2; set `"1.3"` where your policy allows), automatic certificates through ACME or uploaded certificates, HSTS (on by default), TLS to the origin (`upstreams.tls`), and mTLS for selected API paths. The control plane listener uses TLS.

**What you still do**: inventory certificates (4.2.1.1), choose protocol and cipher policy, keep `upstreams.tls.insecure_skip_verify` off, and encrypt the hop to the origin whenever it leaves a trusted segment. Alert on `sherlock_cert_expiry_seconds`.

## What to configure: checklist

- [ ] Every in-scope site is in `mode: block`; no in-scope endpoint disables the WAF; origins accept traffic only from Sherlock.
- [ ] `fail_mode: closed` on in-scope sites.
- [ ] Paranoia level and exclusions reviewed after the detect-mode rollout; the would-block report is quiet.
- [ ] Virtual patches enabled and stacks declared (`policy.stacks`).
- [ ] Login protection on the login endpoints; data protection on pages that can show card data (defence in depth).
- [ ] Both audit and event streams exported to the central log server with a spool size (`spool_max_mb`) sized for your longest tolerated outage.
- [ ] Alert rules for blocks, dropped events, unhealthy upstreams and expiring certificates; alerts on Sherlock's own metrics in your monitoring.
- [ ] `sherlock audit verify` on a schedule; results retained.
- [ ] NTP on every node.
- [ ] MFA enrolled for every user; lock maximum at least 30 minutes; unused accounts and tokens removed; admin listener restricted by `global.admin.allowed_cidrs`.
- [ ] TLS minimum version, HSTS and certificate monitoring set; TLS to origins.
- [ ] Retention for events and audit rows defined in your central store (12 months, 3 months online).
- [ ] Sherlock and the rule set updated on a schedule, with dates recorded.
