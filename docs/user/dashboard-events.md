# Investigate attacks: explorer, event detail, analytics, would-block report

These dashboard pages need the `events:read` permission (every built-in role has it). They read stored security events, so retention applies ([control plane](control-plane.md)).

## Attack explorer (`/events`)

Search and filter events, newest first.

1. Pick a **time range** (15 minutes to 7 days, or a custom range).
2. Narrow by **site**, **action** (allow, log, challenge, block, rate limit, ban), **rule ID**, **client IP**, **country** (two letters), **method**, **status** or free text (path, host, client address, rule IDs). Choose **Apply filters**; **Reset filters** clears them.
3. The table pages with **Older events** / **Newer events**. On the first page, live updates refresh it every few seconds; use **Pause live updates** to read without rows moving.
4. Open a row to see the event.

Filters live in the URL, so you can bookmark or share a view with a colleague who has the same permission.

## Event detail (`/events/<id>`)

Everything recorded for one request: summary and action, the request (method, host, path, query, headers, body excerpt), the response, the client (IP, country, ASN, reputation), timings and the findings (rule, module, severity, score, message, matched value). Use **Show them in the explorer** to list other events that matched the same rule in the last 24 hours, or a rule link to filter by that rule. Values come from the attacker and are always shown as plain text.

An event can be missing if retention deleted it.

## Analytics (`/analytics`)

Traffic and attack trends for a time range and, optionally, one site: requests by action over time, and the top sites, rules, client IPs, paths and countries. Every chart has a table with the same numbers (**View as table**). A note says when a panel was computed from a capped sample, so counts are approximate.

## Would-block report (`/reports/would-block`)

For sites in **detect** mode: the requests that would have been blocked, grouped by rule and by path, with the most recent requests and a **Export CSV** button. Use it before switching a site to block mode; reading it is covered step by step in [roll out from detect to block](detect-to-block.md). If the report says counts are a lower bound, more requests matched than were analysed; shorten the range.

## Bot defence tab (`/sites/<site>/bot`)

Configure the challenge for a site: turn it on, choose proof of work, Cloudflare Turnstile or hCaptcha, set difficulty and clearance lifetime, decide what to do with verified search engine bots and add ordered rules (paths, methods, countries, bad reputation) with an action each. Turnstile and hCaptcha need their secret in the server environment (`SHERLOCK_TURNSTILE_SECRET`, `SHERLOCK_HCAPTCHA_SECRET`); the dashboard only takes the public site key. The tab also shows challenges issued, passed and failed in the last 24 hours. Changing it needs `config:write`; viewers see it read-only.

## System page (`/system`)

Needs `system:read`. It shows the version, CRS version, database, config version and audit chain head, event storage (stored, published, dropped, data directory size, retention), data feed health and the node's own backups (file, time, size, encrypted).

**Updates.** Choose **Check for updates** to contact the signed release manifest. The result is cached for five minutes.

- If a release is available and you hold `system:update`, **Stage update** appears. After you confirm, Sherlock downloads, verifies and **stages** the update. It does **not** restart: the new version runs only after you restart the service, and the unit installs the staged bundle at the next start ([upgrade](upgrade.md)). A "staged, waiting for restart" line stays visible until then.
- Viewers see the status but no button.
- In a container the button is hidden: pull a new image instead. Some releases cannot be installed from the dashboard (for example when you must upgrade through an intermediate version); the reason is shown.
- "Not supported on this node" (501) and "release server could not be reached" (502) are shown as messages; the rest of the page keeps working.
