# Login protection

Login protection stops credential stuffing and password guessing against your own sign-in pages. Sherlock counts **failed** logins per client address, per account and per browser (device), and when one of them goes over its limit it challenges or blocks the next attempt. Everything is under `policy.login_protection`, at the global defaults, a site or an endpoint.

In `detect` mode nothing is enforced: a client over a limit only produces a finding (`login-ip`, `login-username` or `login-device`, action `log`), so the would-have-blocked report shows what would happen. Switch the site to `block` to enforce.

## Declare your login endpoints

Nothing is watched until you say where your login is. Sherlock cannot guess which requests are logins, and it never reads any other request body.

```yaml
policy:
  mode: block
  bot: { enabled: true }          # needed for action: challenge (see below)
  login_protection:
    enabled: true
    endpoints:
      - path: /api/login           # glob; "/api/*" also covers everything below it
        method: POST               # default POST
        username_field: email      # a form field, or a JSON pointer such as /user/email
        failure_statuses: [401, 403]   # what your application answers to a bad login (the default)
    thresholds: { per_ip: 20, per_username: 5, per_device: 10, window: 10m }
    action: challenge              # challenge (default) | block | log
```

- `username_field` names the field that holds the account name. For a form body (`application/x-www-form-urlencoded`) it is the field name. For a JSON body (`application/json` or `+json`) a plain name is a top-level key, and a value starting with `/` is a JSON pointer (`/user/email`, `/creds/0/name`). Multipart bodies are not read; the account counter is then skipped for that request and the address and device counters still apply.
- A request is a **failed login** when your application's answer has one of `failure_statuses`. Applications that answer a bad password with `200` and an error page cannot be watched by status; change them to `401`, or add the status they use.
- Successful logins are never counted. A customer who signs in correctly is never slowed down by their own history.
- Up to 20 endpoints per policy. `endpoints` is a list: a site that sets it replaces the global list.

## Thresholds

`per_ip`, `per_username` and `per_device` are how many failed logins are allowed per `window` (1 minute to 24 hours) before the next attempt gets the action. The window slides: failures fade out over about one window, and refused attempts are not counted, so a tripped counter always drains. Defaults: 20 per address, 5 per account, 10 per device, 10 minutes.

| Scope | Counts failures of | Catches | Watch out for |
| --- | --- | --- | --- |
| address | one client address | one machine guessing | Many customers behind one office or mobile-carrier address share it. Keep it well above what a household or office produces. |
| account | one username, from anywhere | a botnet guessing one account from many addresses | See "Account lock-out" below. |
| device | one browser fingerprint, from anywhere | one tool rotating addresses | Many people with the same browser build share a fingerprint, so it is only a hint. Keep it high, or prefer `challenge`. |

The fingerprint is a hash of a few stable headers (User-Agent, Accept-Language, Accept-Encoding, client hints, which common headers are present) and the TLS version and cipher. It is not unique to a person and it is not JA4 (the embedded server does not expose it).

How to size: look at the failed logins your application records on a normal day. Set `per_ip` above the busiest honest address, `per_username` at the number of mistakes a customer realistically makes in a few minutes (3 to 5), and start in `detect` mode to read the findings before enforcing.

## What the action does

- **`log`**: only a finding. Use it to measure.
- **`block`**: the attempt is refused with `429` and `Retry-After` (the window). The origin never sees it.
- **`challenge`** (default): the attempt is refused with `403`, and Sherlock's bot module then serves its challenge page to that address and to that browser fingerprint on their next page request. When the visitor solves it, they get a clearance cookie and are exempt from login limits (not from other protections) until it expires. API clients and scripts cannot solve a challenge, which is the point. `challenge` needs `bot: { enabled: true }` on the site; without it Sherlock enforces `block` instead, as the rate limiter does.

A client over a limit is refused **before** the origin sees the request, and failures are recorded **after** the origin answers. So the attempt that reaches the limit is still answered normally, and the next one is the first refused.

Allow-listed addresses are never counted or refused.

## Account lock-out: what an attacker can do

Counting failures per account has a cost: someone who knows a username can fail logins on purpose and put that account over its limit for everyone, including its owner. Sherlock limits the damage:

- Only the account's own counter decides. Failures on other accounts, other addresses or other browsers do not move it, and the attacker's failures do not make the owner's address or browser count as bad.
- With `challenge`, the owner is not locked out: their next attempt is refused once, they are shown the challenge, and after solving it they sign in. This is why `challenge` is the default.
- With `block`, the owner is refused until the window slides past the attacker's failures (up to `window`). Choose `block` for accounts where that is acceptable, or keep `per_username` high and rely on the address and device counters.

## Privacy

Usernames are used only as a **keyed hash** (HMAC-SHA256 with a random key created when the process starts) inside in-memory counters. The name and the hash are never written to findings, events, logs, exports or metric labels, and the counters disappear when the process stops. Findings say which scope tripped ("failed logins from this account reached the limit"), never whose account it was. Passwords are never read.

## Metrics and events

- `sherlock_login_failures_total{site}`: failed logins seen on declared endpoints.
- `sherlock_login_actions_total{site,action,scope}`: decisions taken (`challenge`, `block`, `log`; scope `ip`, `username`, `device`).
- Events carry findings from module `login`: `login-ip`, `login-username`, `login-device` when a request was acted on, and `login-<scope>-threshold` (a notice) on the request that reached a limit.

## Limits to know about

- Counters are per process. With several nodes behind one load balancer, the effective limit is the setting times the number of nodes (shared counters arrive with multi-node support).
- Only the first 64 KiB of a body is read to find the username; a larger body (or a type that is not form or JSON) is passed on whole but has no account counter, so an attacker who pads bodies still meets the address and device limits.
- Counters use bounded memory (about a million keys); under extreme key churn the least recently used keys are forgotten first, which can only make the module more lenient.
