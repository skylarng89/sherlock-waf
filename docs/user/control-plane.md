# Running the control plane

`sherlock run` without `--config` starts the full node: the data plane (the WAF proxy) driven by a database, plus the API and dashboard over TLS. `sherlock run --config sherlock.yaml` still runs the data plane alone from a file (see the file-config quickstart).

## First start

A fresh node has **no users and no configuration**, and no default password. Either create the first administrator from the command line:

```sh
sherlock user create --admin ada          # prompts for a password (12+ characters)
sherlock run                              # API on https://127.0.0.1:9443
```

or start the server and use the dashboard's setup page: it asks for the one-time setup token, which the server wrote to `<data-dir>/setup-token` (mode 0600; the log names the file but never prints the token). The token works once and the page closes itself as soon as a user exists.

The server logs the SHA-256 of its public key (`tls_spki_sha256`) at start. The certificate is self-signed until you supply your own (`SHERLOCK_ADMIN_TLS_CERT` and `SHERLOCK_ADMIN_TLS_KEY`); pin the logged value when you script against it.

Sign in through the dashboard or API. Every account must enrol an authenticator app at first sign-in.

## Where state lives

| Setting | Default | Notes |
| --- | --- | --- |
| `--data-dir` | `$XDG_DATA_HOME/sherlock` | node key (`node.key`, mode 0600), TLS identity, SQLite database, event files |
| `--database-url` / `SHERLOCK_DATABASE_URL` | `<data-dir>/sherlock.db` | `postgres://…` or a SQLite path |
| `SHERLOCK_ADMIN_LISTEN` / `--listen` | `127.0.0.1:9443` | control plane address |
| `SHERLOCK_ADMIN_ALLOWED_CIDRS` | any | comma-separated CIDRs allowed to connect |
| `SHERLOCK_NODE_KEY_FILE` | `<data-dir>/node.key` | key that encrypts stored secrets; back it up with the database |

Until a configuration exists the node is alive (`/healthz`) but not ready (`/readyz` is 503) and proxies nothing. The first `PUT /api/v1/config` (or `sherlock config import`) needs no `If-Match`; later changes do.

## Command line

```sh
sherlock user create|reset-password|reset-mfa <username>
sherlock token create --user ada --name ci --scope write [--cidr 10.0.0.0/8] [--expires-in 720h]
sherlock config validate sherlock.yaml          # offline check, touches nothing
sherlock config export [-o sherlock.yaml]       # live configuration as YAML
sherlock config import sherlock.yaml            # fresh node only
sherlock config apply  sherlock.yaml            # replace; no-op when identical
sherlock hash-password                          # argon2id hash for a site password gate
sherlock audit verify                           # checks the audit hash chain
sherlock secrets rotate-key                     # re-encrypt secrets under a new node key
sherlock backup [--output F] [--include-key] [--passphrase-stdin] [--files-only]   # safe while running
sherlock backup verify FILE | list              # check an archive end to end; list <data-dir>/backups
sherlock restore FILE [--force] [--passphrase-stdin]   # server stopped
sherlock update [--check | --bundle FILE | --rollback]  # signed releases; see upgrade.md
```

Guides: [install](install.md), [first site](first-site.md), [detect to block](detect-to-block.md), [backup and restore](backup-restore.md), [upgrade](upgrade.md), [TLS and certificates](tls-certificates.md), [users, tokens and the audit log](users-tokens-audit.md), [virtual patching](virtual-patching.md).

Passwords are read from a prompt, or from stdin with `--password-stdin`; never from a flag or the environment. `token create` prints the secret once on stdout.

`config import|apply` and `secrets rotate-key` change state that a running server holds in memory, so by default they refuse to run while a server is using the data directory. Against a running node, use its API instead:

```sh
sherlock config apply sherlock.yaml --server https://127.0.0.1:9443 --token "$SHERLOCK_TOKEN" --tls-pin <spki-sha256>
```

Rotating the node key needs the server stopped.

## Export and import

`config export` followed by `config import` on a fresh node reproduces the same configuration, and therefore the same compiled proxy configuration.

## Request validation

Every API request is checked against the published OpenAPI document (`api/openapi.yaml`) before it is processed. Clients see the result as a problem document:

| Status | When | Body |
| --- | --- | --- |
| 415 | the body's `Content-Type` is not one the endpoint documents (JSON endpoints take `application/json`, `PATCH` takes `application/merge-patch+json`) | problem document |
| 400 | the JSON is malformed, a required body is missing, or the body is larger than 4 MiB | problem document |
| 422 | a value breaks the schema: a value outside its allowed set, a bad pattern or length, an out-of-range number, an unknown field on a configuration object | `errors` lists `path` (JSON pointer into the request body, for example `/username`, or `/query/step` for a parameter), `code` and `message` |

Requests to endpoints that need a session or token are refused with 401 or 403 before validation runs, so the schema is not revealed to callers who are not signed in or not authorised.

## Secrets in API responses

A site's password gate stores an argon2id hash (`policy.acl.password_gate.password_hash`, at the global defaults, site and endpoint level). The API never returns it: `GET /config`, `/defaults`, `/sites`, `/sites/{site}`, `/sites/{site}/endpoints[/{endpoint}]` and `/config/versions/{id}` show the literal string `<redacted>` instead, for every caller including administrators. Writes treat the field like this:

| You send | Result |
| --- | --- |
| a real `$argon2id$...` hash | it replaces the stored one |
| `"<redacted>"` (a read-modify-write round trip) | the stored hash for the same site and endpoint id is kept |
| the field omitted | the stored hash is kept |
| `"<redacted>"` or nothing for a gate that has no stored hash (a new site, another site's id) | no hash: validation says the hash is required |

The hash is matched by site and endpoint id, so it can never move to another site, and the stored value is never overwritten with the placeholder. A hash cannot be removed by omitting it: disable the gate (`enabled: false`) or delete the site. Note that JSON encoders in some languages escape `<` and `>` (`"\u003credacted\u003e"`); that decodes to the same string. `sherlock config export` on the node (no `--server`) still writes the real hashes, because it reads the database directly with operator access; over `--server` it receives the placeholder.

## Your account and sessions

Every signed-in user has an **Account** entry in the account menu (top right). It shows two things.

**Change password.** Enter your current password, then a new one of at least 12 characters that differs from it and is not a common password. If your account has two-step verification, also enter the current 6-digit code from your authenticator app; a session cookie and the password alone cannot change the password. A code works once: the new password is checked against the policy first, so a refused new password does not cost you a code, but a code that was already used for sign-in (or for an earlier attempt that got past the policy check) is refused, so wait for the next one. Common passwords are checked against a list of breached passwords of 12 or more characters, with trailing digits and symbols removed and common letter-for-symbol swaps decoded, so `Summer2024!` is refused if its base word is on the list. If another change to your password commits while yours is being checked, yours is refused with `409 password changed concurrently` and nothing changes; sign in again with the password that won. On success your other browser sessions and devices are signed out, and this one stays signed in. Wrong current passwords are refused with a message on the field and counted: five attempts a minute are allowed, then the page reports that you must wait. A failed attempt never locks the account, and an administrator can still reset the password. Every change is recorded in the audit log as `user.password_changed` (the number of sessions it ended, never a password); failures are recorded as `user.password_change_failed` with a reason.

**Signed-in sessions.** The table lists each full browser session signed in as you, with when it started, when it was last active and when it expires. Sign out any session you do not recognise with its **Sign out** button, which asks for confirmation. Your current session has no button: use **Sign out** in the account menu to end it.

**Session cap.** A user has at most five full sessions at a time. Signing in on a sixth browser or device signs out the oldest session, and the audit log records `auth.session_evicted`. Sessions that are still completing two-step verification are not counted.

Users who have not finished two-step verification do not see the account menu, and the API refuses them the account operations too.

## API tokens

Tokens are for scripts and integrations. Each token has a name, scopes, optional networks and an expiry.

- **Maximum lifetime.** A token may live at most `SHERLOCK_API_TOKEN_MAX_DAYS` days (default 365; `0` removes the limit; see [deployment](../operations/deployment.md)). A token created without an expiry gets that maximum. An expiry beyond the maximum is refused on the expiry field. The create form on the API tokens page states the limit for this node.
- **Expiring soon.** A token that expires within 14 days carries an **Expires soon** badge in the table. Create a replacement before the old one stops working.
- **Per-account cap.** An account holds at most 50 tokens. Revoke one before creating another.
- **Applying updates.** `POST /system/update/apply` (the dashboard's update button, or the API) needs a browser session with the `system:update` permission. An API token is refused with 403 even when its scopes would otherwise allow it.
- **Failed presentations.** A client address that presents bad tokens more than 10 times a minute is refused with 429 for the rest of the minute, even with a valid token. Failures are audited as `auth.token_failed`, at most one row a minute per address, carrying a count. The presented token is never recorded.
- The CLI (`sherlock token create`) applies the same maximum and cap as the API.

## Request limits

Every control-plane request counts against a limit. A signed-in user or a token may make 300 requests a minute. An anonymous caller of a public operation (sign-in, setup status and the like) may make 120 a minute from one address. Login and setup have stricter limits of their own. A refused request gets `429` with `Retry-After`, and the `sherlock_api_throttled_total` metric counts it by scope. Requests that fail authentication do not use anyone's budget. The dashboard polls at most every five seconds, far below the limit.
