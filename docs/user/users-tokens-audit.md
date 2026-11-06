# Users, sign-in security, API tokens and the audit log

This page covers who can do what in the control plane, how sign-in is protected, how scripts authenticate, and how to read and verify the record of what happened. For starting the server and the command line overview, see [running the control plane](control-plane.md).

## Roles and permissions

There are two roles. Every account has exactly one.

| Permission | Viewer | Admin |
| --- | --- | --- |
| Read configuration, sites, certificates, tuning (`config:read`) | yes | yes |
| Change configuration (`config:write`) | no | yes |
| Read security events (`events:read`) | yes | yes |
| Manage users (`users:manage`) | no | yes |
| Read the audit log (`audit:read`) | no | yes |
| Read system information (`system:read`) | yes | yes |
| Apply a software update (`system:update`) | no | yes |
| Create and revoke your own API tokens (`tokens:own`) | yes | yes |

Permissions are enforced on the server for every request; hiding a button in the dashboard is a convenience, not the control. An administrator cannot remove or disable the last enabled administrator (the request is refused with `409`).

## Creating and managing users

- **Dashboard.** **Users** (administrators only) lists accounts and lets you create one, change its role, disable or enable it, set a new password (**Reset password**) and reset its authenticator (**Reset MFA**). Changing a role, disabling an account or setting a new password ends that user's sessions.
- **API.** `GET /users`, `PATCH /users/{id}` (`role`, `disabled`, `password`), `DELETE /users/{id}` (removes the user's sessions and tokens too) and `POST /users/{id}/reset-mfa`.
- **Command line**, on the node, for the first administrator or when you are locked out:

  ```sh
  sherlock user create --admin ada               # prompts for a password; --role viewer is the default role
  sherlock user create --role viewer vic --password-stdin < pw.txt
  sherlock user reset-password ada               # new password, clears any lock, ends the user's sessions
  sherlock user reset-mfa ada                    # clears the authenticator, ends the user's sessions
  ```

Passwords must be at least 12 characters, must not be a common or breached password (the check also catches simple variations such as `Summer2024!`) and are stored hashed with argon2id.

## Two-step verification

Every account must enrol an authenticator app (TOTP) at first sign-in, and every later sign-in asks for a 6-digit code. There is no way to turn it off. A code can be used once: replaying the same code is refused.

**Lost authenticator.** There are no recovery codes. An administrator clicks **Reset MFA** for the user (or `POST /users/{id}/reset-mfa`), or you run `sherlock user reset-mfa <username>` on the node. The user's sessions end and they enrol a new authenticator at the next sign-in. If the only administrator loses their authenticator, use the command line on the node.

## Sessions

A signed-in browser holds a session cookie. Two limits apply:

- **Five full sessions per user.** Signing in on a sixth browser or device signs out the oldest, and the audit log records `auth.session_evicted`. Sessions that are still completing two-step verification do not count.
- **Account page.** Every user has **Account** in the account menu. It lists their signed-in sessions with start, last activity and expiry, and lets them sign out any session except the current one (use **Sign out** for that). `GET /auth/sessions` and `DELETE /auth/sessions/{id}` do the same; an id that belongs to another user is answered as not found.

## Changing your password

On the **Account** page enter the current password and a new one. If your account has two-step verification, which it always does after first sign-in, the form also asks for the current 6-digit code. A stolen session cookie and password are therefore not enough to take over the account.

- The code is checked after the new password passes the policy, so a password that is refused does not use up your code.
- A code that you used to sign in a moment ago is refused; wait for the next one.
- Wrong current password: refused on that field. Attempts are limited to five a minute, and a failed attempt never locks the account.
- On success your other sessions end and this one stays signed in.
- If another change to the same password commits at the same moment, yours is refused with `409` and nothing changes.

Through the API, `POST /auth/password` takes `current_password`, `new_password` and `totp_code`. Without a code, or with a wrong one, the answer is `422` naming `/totp_code`.

## Sign-in throttling and lockout

Sign-in is limited to slow down guessing. The defaults can be changed with environment variables on the server (they are read at start; a value that is not a whole number in range stops the server with an error rather than being ignored):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHERLOCK_LOGIN_IP_ATTEMPTS` | `5` | Attempts a minute from one client address, and from one address for one username. |
| `SHERLOCK_LOGIN_USER_ATTEMPTS` | `20` | Attempts a minute for one username from all clients together. |
| `SHERLOCK_LOGIN_LOCK_AFTER` | `4` | Consecutive failures before the account locks. `0` turns locking off. |
| `SHERLOCK_LOGIN_LOCK_MAX_MINUTES` | `15` | The longest lock, 1 to 1440. A lock starts at one minute and doubles with each further failure up to this value. |

Throttled attempts are answered with `429` and a `Retry-After`. Locking has a cost: anyone who knows a username can keep that account locked by failing on purpose. An administrator can unlock the account by resetting its password, and `SHERLOCK_LOGIN_LOCK_AFTER=0` removes the effect (the rate limits stay in force). The counters are kept in the memory of each server process, so on several nodes the effective limits are the configured numbers times the node count.

Other requests are limited too: a signed-in user or token may make 300 control-plane requests a minute, and a client address that presents bad API tokens more than 10 times a minute is refused for the rest of the minute.

## API tokens

Tokens are for scripts and integrations. A token is created from a signed-in browser session (**Tokens** in the dashboard, or `POST /tokens`) or on the node with the command line:

```sh
sherlock token create --user ada --name ci --scope write --cidr 10.0.0.0/8 --expires-in 720h
```

The secret has the form `shk_<id>_<secret>`. It is shown **once**, when the token is created; only a hash is stored, so a lost token must be replaced. Send it as `Authorization: Bearer shk_...`.

| Setting | Meaning |
| --- | --- |
| Scopes | `read` (read configuration and system information), `write` (read plus change configuration), `events:read` (read events only), `admin` (everything an administrator has except creating tokens). At least one is required. |
| Allowed networks | Optional CIDRs. A token presented from any other address is refused. |
| Expiry | Optional, in the future. A token created without one gets the maximum lifetime. |
| Maximum lifetime | `SHERLOCK_API_TOKEN_MAX_DAYS`, default `365`; `0` removes the limit. An expiry beyond the maximum is refused. The dashboard and the command line apply the same limit. |
| Count | At most 50 tokens per account. Revoke one before creating another. |

A token's permissions are the intersection of its scopes and its owner's role, so demoting a user also narrows their tokens. A token never carries `tokens:own`: tokens cannot create more tokens. Applying a software update is refused for tokens even with the `admin` scope; it needs a browser session. Revoke a token from the Tokens page or with `DELETE /tokens/{id}` (an administrator may revoke any).

## The audit log

Every administrative action and every security-relevant sign-in event is recorded in the audit log, in the same database transaction as the change itself: if the change rolls back, so does its audit row. Administrators read it on the **Audit** page or with `GET /audit` (newest first, `limit` and `before_seq` for paging).

**What is recorded.** Who (user, token or the system), when, from which address, what (the `action`), on which object, and a small JSON `details` object. Typical actions:

| Area | Actions |
| --- | --- |
| Sign-in | `auth.login`, `auth.login_failed`, `auth.login_throttled`, `auth.login_locked`, `auth.account_locked`, `auth.password_ok`, `auth.mfa_enrolled`, `auth.logout`, `auth.session_evicted`, `auth.session_revoked`, `auth.token_failed`, `auth.denied`, `setup.admin_created` |
| Accounts | `user.create`, `user.update`, `user.delete`, `user.reset_password`, `user.reset_mfa`, `user.password_changed`, `user.password_change_failed` |
| Tokens | `token.create`, `token.revoke` |
| Configuration | `config.apply`, `config.apply_failed`, `config.rollback`, `virtual_patches.enabled`, `virtual_patches.disabled` |
| Assets | `certificate.upload`, `certificate.delete`, `ca_bundle.upload`, `ca_bundle.delete`, `api_doc.put`, `api_doc.delete`, `block_page.put`, `block_page.delete`, `exporter.put`, `exporter.delete` |
| Operations | `ban.create`, `ban.lift`, `ban.auto`, `backup.create`, `backup.restore`, `system.update`, `system.update_failed`, `system.test_upstream` |

Failed sign-ins for unknown users and throttled attempts are recorded under the actor `anonymous`. Repeated bad API tokens from one address are coalesced into one `auth.token_failed` row a minute with a count.

**What is never recorded.** Passwords (current or new), TOTP codes, session identifiers, API token secrets and values, private keys, HMAC secrets and the credentials inside exporter or channel settings. The audit writer enforces this: a detail key that looks like a credential (it matches `password`, `secret`, `totp`, `private`, `authorization`, `cookie`, `token`, `key`, `api key` or `session id`) makes the write fail instead of storing it. Exporter changes record the type, stream and enabled flag only.

**Tamper evidence.** Each row stores the hash of the previous row, so editing or removing a row in the middle breaks the chain from that point on. Check it any time:

```sh
sherlock audit verify
```

It reads the whole log and reports `audit chain intact: <n> entries, head seq <s> hash <h>`, or names the first sequence number where the chain is broken (a gap, a wrong link, or a row whose contents no longer match its hash) and exits non-zero. It also checks that the log ends at the recorded head, which catches deleted newest entries.

The honest limit: someone who can write the database directly can rewrite the newest entries and recompute every hash after the edit. To close that gap, keep a copy of the head somewhere the database owner cannot change. The server logs `audit checkpoint` with the head sequence and hash every five minutes; ship those log lines to your log pipeline and compare them with the output of `sherlock audit verify`.

**Exporting.** Send the audit log to your SIEM as it is written by creating an exporter with stream `audit` (or `both`); records use the schema `sherlock.audit.v1` and carry a stable id for deduplication. See [exporters and alerts](exporters-and-alerts.md). Sherlock does not delete audit rows.
