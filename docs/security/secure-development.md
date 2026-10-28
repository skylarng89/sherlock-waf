# Secure development rules

These apply to every change, whoever wrote it. Authors must follow them; reviewers must check them.

## Non-negotiables

1. **No secrets in the repo.** Use `.env.example` with placeholders. `gitleaks` runs in pre-commit and CI.
2. **No disabling of security checks** to make CI green (lint rules, tests, `go-ftw` cases, CSP). If a check is wrong, change it in its own PR with a reason.
3. **Human review required** for any change touching: `internal/controlplane/auth`, `internal/controlplane/api` middleware, `internal/dataplane/waf`, `internal/dataplane/core`, `internal/updater`, `internal/store` migrations, crypto code, `pkg/extension`. CODEOWNERS enforces this.
4. **No new dependency without a reason** in the PR description: maintenance status, licence (must be compatible with AGPL-3.0 and with distribution under the commercial licence: MIT, BSD, Apache-2.0, MPL-2.0, ISC are fine; GPL/AGPL dependencies need explicit approval), and size. `go-licenses` and `license-checker` run in CI.
5. **Crypto**: only Go standard library and `golang.org/x/crypto`. argon2id (time=3, memory=64 MiB, threads=2) for passwords; XChaCha20-Poly1305 for secrets; HMAC-SHA256 for tokens; `crypto/rand` only.
6. **Input handling**: every API input validated against the OpenAPI schema plus domain validation; never build SQL strings (sqlc only); never pass user input to a shell.
7. **Output handling**: no `v-html` in the dashboard except for sanitised Markdown help text (lint rule `vue/no-v-html` set to error); JSON responses only from typed structs.
8. **Errors**: no stack traces or internal paths in API responses; log them with a request ID instead.
9. **Logging**: never log passwords, tokens, cookies, `Authorization`, TOTP codes, PANs. Use `slog` with the redacting handler in `internal/logging`.
10. **Defaults are secure**: new options default to the safer choice; document the trade-off when a user turns it off.

## Review checklist

Paste into the PR description and tick:

- [ ] I read every line of the diff in the security-sensitive paths above.
- [ ] Tests cover the failure paths, not only the happy path.
- [ ] No new network call on the request path.
- [ ] No new dependency, or the dependency is justified.
- [ ] Error messages leak nothing internal.
- [ ] Permissions: new API routes declare `x-sherlock-permission`.
- [ ] Threat-model items for this area re-checked.
- [ ] Docs updated (user docs and these design docs if behaviour changed).

## Standards

- OWASP ASVS 5.0 Level 2 for the control plane.
- OWASP Top 10 and API Security Top 10 as test categories.
- CIS-style hardening in the systemd unit and container image (non-root, read-only root FS, no new privileges, capabilities only `CAP_NET_BIND_SERVICE`).

## Vulnerability handling

See [../../SECURITY.md](../../SECURITY.md). Target fix times after triage: critical 7 days, high 30 days, medium next minor release.
