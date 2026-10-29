# Access control, rate limits and bans

These checks run before the WAF and are cheap (an address lookup), so they take load off Coraza. They apply in every mode, including `detect` and `off`: an explicit deny list or rate limit is a control you chose, not a detection.

## Order of evaluation

1. **Temporary ban** (manual, automatic, or from CrowdSec) — 403.
2. **Deny list** — 403.
3. **Allow list** — the client is exempt from everything below *and* from rate limits and bot checks, but **still inspected by the WAF** unless you set `acl.allow_bypass_waf: true`.
4. **Country rule** (`allow` or `deny` list of ISO country codes). Private addresses and addresses missing from the database are never denied by it, and with no database loaded the rule stays silent rather than blocking everyone.
5. **Reputation** (FireHOL level 1, Spamhaus DROP) — `block` or `log`.
6. **Password gate** (HTTP Basic, argon2id hash) — 401 until the right credentials are sent. Allow-listed clients skip it.
7. **Rate limits** — 429 with `Retry-After`.

A client on both an allow list and a deny list is denied.

## Configuration

```yaml
global:
  ip_lists:
    - { name: office, cidrs: ["203.0.113.0/24"] }
    - { name: known-bad, cidrs: ["198.51.100.7"] }
  feeds:
    geoip: { provider: dbip-lite, auto_update: true }
    reputation_lists: [firehol_level1, spamhaus_drop]
    crowdsec: { enabled: true, lapi_url: "http://127.0.0.1:8080", allow_private: true }
  defaults:
    rate_limits:
      - { name: per-ip, limit: 600, window: 1m }          # key defaults to ip, action to block

sites:
  - id: shop
    hosts: [shop.example.com]
    upstreams: { targets: ["10.0.0.5:8080"] }
    policy:
      acl:
        allow_lists: [office]
        deny_lists: { add: [known-bad] }                    # edit the inherited list instead of replacing it
        countries: { mode: deny, list: [KP] }
        reputation: { enabled: true, action: block }
      rate_limits:
        - { name: login, match: { paths: ["/api/login"], methods: ["POST"] }, limit: 10, window: 1m }
      auto_ban: { blocks_threshold: 20, window: 5m, ban_duration: 30m }
    endpoints:
      - id: health
        match: { path: /healthz }
        policy: { opt_out: ["rate_limits:per-ip"] }         # the only way to drop a global item
```

**Merge rules.** Lists of names (`allow_lists`, `deny_lists`) written as a sequence *replace* the inherited list; written as `{add, remove}` they *edit* it. Rate limits are named items: levels are unioned by name, a lower level replaces an item with the same name, and `opt_out` removes an inherited item. `GET /sites/{site}/effective-policy` shows every resolved value and the level it came from.

**Rate limits.** `match.paths` are `path.Match` globs; `/api/*` also covers everything below `/api/`. `key` is `ip` or `header:<name>` (a request without the header falls back to the client address). Counting is a sliding window (two-bucket approximation) held in memory; the number of tracked keys is capped, so a client rotating keys cannot grow memory. `action: challenge` is enforced as a block until the bot module arrives.

**Auto-ban.** Counts blocks per client per site; after `blocks_threshold` blocks inside `window` the client is banned for `ban_duration`. It is a per-site setting taken from the site-level policy. Allow-listed clients and clients already denied by the ACL do not count. Automatic bans are stored, audited, and survive a restart.

**Password gate.** Create the hash with `sherlock hash-password` and paste it into `acl.password_gate.password_hash`. The clear password is never stored. Failed attempts are throttled per client.

## Feeds

The feeds job refreshes in the background and swaps data atomically, with no restart and no dropped requests. A failed download keeps the previous data and shows as `failed` (or `stale` after a long time) on the Access page and in `GET /feeds/status`.

- **GeoIP** — DB-IP Lite country data. With `auto_update` it downloads the current month's file (falling back to the previous month) into `<data-dir>/geoip/`. To work offline, place `dbip-country-lite.csv.gz` there yourself. MaxMind is accepted in the configuration but not implemented yet and is reported as failed.
- **Reputation lists** — FireHOL level 1 and Spamhaus DROP. A download that is empty or not a list is treated as a failure, never as "allow everyone".
- **CrowdSec** — polls the local API's decision stream and applies `ban` decisions for single addresses as bans. The API key comes from the environment (`SHERLOCK_CROWDSEC_API_KEY`), never the configuration.

Outbound feed requests refuse loopback, private, link-local (including the cloud metadata address 169.254.169.254), multicast and unspecified addresses, checked on the address actually dialled so DNS tricks and redirects cannot get around it. A CrowdSec API on the same host needs `crowdsec.allow_private: true`; the metadata address stays refused even then.

## Bans

`GET/POST /api/v1/bans` and `DELETE /api/v1/bans/{id}` (the Bans page in the dashboard). A manual ban takes effect immediately without a reload. The server refuses to ban the address you are connecting from.
