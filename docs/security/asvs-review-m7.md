# Internal ASVS 5.0 Level 2 review of the control plane (M7-T9)

- Date: 2026-10-29
- Reviewer: AI agent (Claude), for the owner. This is an **internal, self-review** of the code the same project wrote. It is a gate input, not an independent assessment; an external review is still advisable before general availability.
- Standard: OWASP ASVS 5.0 (chapters V1 to V17), target level 2.
- Scope: the control plane at the repository state of this change: `internal/controlplane/api` (server, middleware, handlers), `internal/controlplane/auth`, `internal/controlplane/tlscert`, `internal/server` (listener, jobs), `internal/audit`, `internal/secrets` (usage only), the new `internal/updater`, `internal/ops` backup/restore, `pkg/cli` commands that touch state, `api/openapi.yaml`, `deploy/systemd/sherlock.service`, `deploy/install/install.sh`. Not in scope: the data plane (`internal/dataplane/*`, covered by go-ftw and its own review), the dashboard (`web/`, another owner), Enterprise extensions.
- Method: read the code paths for each chapter, ran and extended the existing tests, and exercised suspect paths with throw-away tests. Requirement IDs are cited at chapter and topic level, not verbatim, because the full ASVS 5.0 text was not re-read line by line against each item; a reviewer should map the findings to exact requirement numbers when this is signed off.

## Result in one paragraph

No Critical or High findings. Four Medium and several Low findings were fixed in this change (listed first); the remaining items are ticketed with severity below. Phase 2 acceptance criterion 6 (no open critical or high findings) is met. Two Medium items stay open and should be closed before general availability: S-01 (no self-service password change) and S-02 (request bodies are not validated against the OpenAPI schema constraints).

## Fixed in this change

| ID | Severity | ASVS area | Finding | Fix |
| --- | --- | --- | --- | --- |
| F-01 | Medium | V15 (secure coding, SSRF), V13 | `POST /system/test-upstream` dialled any `host:port` with a plain HTTP client. A `config:write` principal (a scoped token is enough) could probe the cloud metadata address `169.254.169.254` or any link-local address and learn reachability and the HTTP status, contradicting the project SSRF rule. | The probe now uses the `netx` client with `AllowPrivate: true` (private upstreams stay testable) which always refuses link-local, multicast and unspecified addresses, checked on the dialled address (DNS rebinding safe). Result class `blocked`. Test: `TestTestUpstreamRefusesMetadataAndLinkLocal`. |
| F-02 | Medium | V14 (data protection), V8 | The site password-gate hash (`password_hash`) was returned in `GET /config`, `/defaults`, `/sites`, `/sites/{site}`, endpoints and `/config/versions/{id}` to every reader, including viewer-role users and `read`-scoped tokens. A hash is offline-crackable. | Redacted to `<redacted>` in all those responses for every caller. On write, `<redacted>` or an omitted field keeps the stored hash, matched by site and endpoint id; a placeholder with nothing stored is cleared so validation fails; the live configuration is never mutated. Documented in `docs/user/control-plane.md`. Tests: `internal/config/redact_test.go`, `TestPasswordHashIsRedactedAndPreserved`. |
| F-03 | Medium | V6 (credential recovery), V16 | `PATCH /users/{id}` with a new password always failed with HTTP 500: the audit entry's detail key `password_changed` matched the audit credential-key guard, so the transaction rolled back. Administrators could not reset a user's password through the API, a broken security control rather than a leak. No test covered it. | Detail key renamed `credentials_changed`. Test: `TestAdminCanResetAPasswordThroughTheAPI` (also asserts sessions end and the password never reaches the audit log). |
| F-04 | Low | V6 (password security) | The password policy was length only (12 to 1024). | Common and predictable passwords of 12+ characters (a short list, repeated characters, straight runs) are refused. This is a floor: see S-06 for the full corpus check. |
| F-05 | Low | V12 (secure communication), V13 | `install.sh` fetched with `curl` defaults (any protocol, any TLS version) and matched the package name in `checksums.txt` as a regular expression. | `--proto =https --tlsv1.2` on every download; exact-field match with `awk`. |
| F-06 | Low | V11, V13 (new code, preventive) | New update and backup paths could have introduced weak links. | Designed with ADR-0017 and tests: Ed25519-signed manifest, offline verification, downgrade refusal, root re-verification of staged data, SSRF-safe client, size caps; backups checksummed, path-validated on restore, AEAD-encrypted when a passphrase is given, `certs/` and the node key excluded by default. |

## Open findings (ticketed)

Severity is the reviewer's estimate of risk in the intended deployment (a single node, control plane on loopback or a private network, reached by a small trusted admin group).

| ID | Severity | ASVS area | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| S-01 | Medium | V6 (authentication lifecycle) | There is no self-service password change. Users depend on an administrator (`PATCH /users/{id}`) or the CLI. A user who suspects compromise cannot rotate their own password, and an admin who resets it learns the new one. | Add `POST /auth/password` (session-bound, requires current password, enforces the policy, ends other sessions, audits). Block release GA on it. |
| S-02 | Medium | V2 (validation), V4 (API) | `docs/security/secure-development.md` rule 6 says input is validated against the OpenAPI schema, but the server has no request validator: `minLength`, `maxLength`, `pattern` and enum constraints in `api/openapi.yaml` are not enforced at runtime (handlers hand-validate, and configuration bodies are strictly decoded). Gaps are mostly bounded by the 4 MiB body cap and domain validation, but a handler that forgets a check has no backstop. | Add `kin-openapi` request validation (already a dependency) in the guard, after authentication, with the strict-decode exceptions kept. Needs a pass over the web client for responses and `readOnly` fields. |
| S-03 | Low | V7 (sessions), V8 | Users cannot list or revoke their own sessions, and the number of concurrent sessions is not limited. Password and role changes and MFA reset do end all sessions, and idle (30 min) and absolute (12 h) limits are enforced. | `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, and a per-user cap. |
| S-04 | Low | V6, V16 | Failed API-token authentication is not audited or throttled. Secrets are 160-bit random and compared in constant time, so guessing is infeasible; the gap is detection (no log of a spraying attempt) and flooding the store with lookups. | Audit `auth.token_failed` with a coarse per-IP limiter, no secret in the record. |
| S-05 | Low | V6, V9 (tokens) | Tokens may have no expiry and no maximum lifetime or count per user. An `admin`-scoped token can also trigger `POST /system/update/apply` (it can only stage a validly signed, newer release). | Optional server-side maximum lifetime (for example 1 year) and an expiry warning; consider keeping `system:update` session-only. |
| S-06 | Low | V6 (password security) | Passwords are not checked against a top-3000 or breach corpus, only against the short list from F-04. | Embed a vetted top-N list (licence check) or an offline k-anonymity checker. |
| S-07 | Low | V6 (anti-automation) | Login lockout and the per-username limiter are keyed on the username, so an attacker can lock out a known administrator (5 attempts per minute, then 1 to 15 minute locks) without knowing the password. This is the usual trade-off against guessing; the CLI can always reset. | Key the limiter on (IP, username) with a larger per-username ceiling, and alert on lockouts. |
| S-08 | Low | V6 (anti-automation) | There is no general API rate limit; only login, the setup token and the update-status cache are limited. The Hasher semaphore bounds concurrent argon2 runs. | A per-principal request limiter in `outer`/`guard`. |
| S-09 | Low | V6, V15 | `POST /setup/admin` hashes the submitted password (argon2id, 64 MiB) before the setup token is checked, so an unauthenticated caller can burn up to four concurrent hashes while setup is open. Bounded by the Hasher semaphore and only possible until the first admin exists. | Check the token's shape and throttle before hashing; consume the token after. |
| S-10 | Low | V16 (logging) | `docs/security/secure-development.md` names a redacting slog handler in `internal/logging` that does not exist. No reviewed code path logs a credential, token, cookie or TOTP code (errors are logged with request ids, details never reach responses), but nothing enforces it. | Implement the handler or correct the document; add a test that logs a secret-shaped attribute. |
| S-11 | Low | V14 | A plain (unencrypted) backup contains Caddy's ACME account and certificate keys and the control plane's TLS private key in clear. Backups are 0600 in a 0700 directory, uploaded-certificate keys are excluded (`certs/`), the node key is never included without encryption, and `SHERLOCK_BACKUP_PASSPHRASE_FILE` encrypts scheduled backups, but encryption is opt-in. | Make encryption the default when a passphrase file exists (done) and document prominently (done); consider an `--encrypt` default in a later major version. |
| S-12 | Low | V13, V11 (supply chain) | The release signing key has no revocation list in the binary, no written rollover procedure, and a source build ships with the `UNSET` placeholder key (updates disabled, fail closed). See ADR-0017 consequences. | Write the key-rollover runbook and generate and commit the real public key before the first release (release blocker for acceptance criteria 2 and 3). |
| S-13 | Low | V16 (audit) | The audit hash chain is not anchored off the box: a database writer can rewrite the newest entries (documented limit in `internal/audit`). Checkpoints are logged periodically. | Ship checkpoints to an external sink (Enterprise signed checkpoints are planned). |
| S-14 | Info | V3, V4 | JSON endpoints do not require `Content-Type: application/json`. CSRF is covered by `SameSite=Strict`, `__Host-` cookies and the double-submit token on all session-authenticated unsafe methods, and bearer tokens are not ambient, so this is not exploitable today. | Reject other content types as part of S-02. |
| S-15 | Info | V8 | `GET /config` exposes `tls.key_file` paths (file-config mode). Paths only, no key material. | None. |
| S-16 | Info | V6 | TOTP is the only second factor (no recovery codes, no phishing-resistant option). That meets L2; WebAuthn is an L3 topic. Recovery is an administrator reset or the CLI. | Roadmap. |

## Chapter notes

| ASVS 5.0 chapter | Assessment |
| --- | --- |
| V1 Encoding and sanitization | JSON responses come from typed structs; problem documents are built from fixed fields. SQL is sqlc only. No shell invocation with user input in the control plane; the new update and backup code runs only fixed `systemctl` arguments and the verified new binary. Conforms. |
| V2 Validation and business logic | Configuration bodies are strictly decoded (unknown fields are errors) and validated with JSON-pointer paths; domain checks exist per handler. Last-admin guard and self-delete guard hold. Gap: S-02. |
| V3 Web frontend security | API sets `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, a `default-src 'none'` CSP, HSTS and `Cross-Origin-Resource-Policy`. No CORS headers (same origin only). The dashboard is out of scope. |
| V4 API and web service | Every operation declares `x-sherlock-permission`; start-up fails on a missing or unknown one; the guard runs before parameter binding. Methods are explicit; undeclared routes return a problem document. 4 MiB body cap; server timeouts set. Gap: S-02, S-08. |
| V5 File handling | Certificate and block-page uploads are size-bounded and parsed, not stored by client name; backup restore rejects absolute, traversal, non-regular and unlisted entries, caps sizes, and extracts only into a private staging directory. Conforms. |
| V6 Authentication | argon2id (t=3, m=64 MiB, p=2), constant-time verify, dummy hash for unknown users, uniform errors, progressive lockout, MFA mandatory with replay protection, setup token single-use and throttled, no default credentials. Gaps: S-01, S-04, S-06, S-07, S-09. |
| V7 Session management | 256-bit random tokens stored hashed, `__Host-` prefixed `HttpOnly`/`Secure`/`SameSite=Strict` cookie, new session on privilege change (a leaked pre-MFA cookie cannot be upgraded), idle and absolute expiry, logout deletes server-side, sessions end on credential, role, disable and MFA reset. Gap: S-03. |
| V8 Authorization | Deny by default, server-side on every route, role and scope intersection, `tokens:own` never granted to tokens, token IDOR handled (404), authorizer errors deny (fail closed), denials audited. New permission `system:update` is admin and `admin`-scope only; the authorization matrix test was extended. |
| V9 Self-contained tokens | Opaque tokens only; no JWT. N/A. Release manifests are Ed25519-signed (ADR-0017). |
| V10 OAuth and OIDC | Not implemented. N/A. |
| V11 Cryptography | stdlib and `x/crypto` only; argon2id, XChaCha20-Poly1305 (secrets, encrypted backups), Ed25519 (releases), HMAC/SHA-256 for token hashes, `crypto/rand` throughout. Node key rotation exists. Backup encryption uses a per-file salt with a counter nonce and a final-chunk flag. |
| V12 Secure communication | Control plane is TLS-only with a minimum of TLS 1.2, a self-signed ECDSA P-256 certificate (renewed automatically, fingerprint logged) or an operator certificate; CIDR allow list fails closed on unparsable peers; loopback by default. Outbound background and update requests go through `netx` (no private or metadata addresses, no environment proxy). |
| V13 Configuration | Secure defaults, secrets from files or the environment (environment discouraged and warned about), hardened systemd unit (no new privileges, `ProtectSystem=strict`, capability bounding). New: `ExecStartPre=-+` runs the verifying `--apply-staged` outside the sandbox; the staged directory is treated as hostile and re-verified. Gap: S-12. |
| V14 Data protection | Secrets sealed at rest, hashes not returned (F-02), setup token never logged, files 0600 and directories 0700, backups checksummed and optionally encrypted. Gap: S-11. |
| V15 Secure coding and architecture | Small packages, wrapped errors, no panics on input, dependencies pinned and scanned in CI, no new third-party dependency added by this change. Fixed: F-01. |
| V16 Logging and error handling | Hash-chained, transaction-bound audit log with a credential-key guard; errors reach clients as problem documents without internals; request ids correlate. New actions audited: `system.update`, `system.update_failed`, `backup.create`, `backup.restore`. Gaps: S-04, S-10, S-13. |
| V17 WebRTC | Not used. N/A. |

## Security-sensitive code that needs line-by-line human review

These are the paths CODEOWNERS already protects plus the new ones this change adds.

- `internal/updater/updater.go` and `manifest.go` (verification order, constant-time compare, in-memory verify-then-extract, atomic swap, `ApplyStaged` re-verification, tar extraction).
- `internal/controlplane/auth/permissions.go` (`system:update`) and `internal/controlplane/api/server.go` (permission table).
- `internal/controlplane/api/handlers_update.go` (apply, audit, write-deadline), `handlers_config.go` and `internal/config/redact.go` (redaction and restoration).
- `internal/ops/backup.go` and `backupcrypt.go` (archive validation, restore moves, AEAD framing).
- `deploy/systemd/sherlock.service` (`ExecStartPre=-+`) and `.github/workflows/release.yml` (signing step).

## Limits of this review

Self-review by the code's author-side agent; no dynamic penetration test; ASVS requirement IDs not individually verified; the dashboard and the data plane are outside the scope; findings are estimates of risk for the stated deployment model.
