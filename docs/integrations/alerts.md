# Alerts and notification channels

An alert rule watches one condition and notifies one or more channels when it becomes true. Rules and channels are managed in the dashboard (Integrations → Alerts, Notification channels) or through `/alert-rules` and `/notification-channels`.

## How rules are evaluated

- A background job evaluates every enabled rule **every 30 seconds**. A condition that is true at a tick notifies within that tick, well inside the 60-second target.
- Evaluation is **per subject**. A rule can have several subjects at once: a site (`blocks_threshold`), a country (`new_country`), a certificate host, a feed, an upstream. Each subject has its own state.
- A subject **fires on its first true evaluation**, then is **silent for the rule's cool-down** (default 900 s, 60 s to 7 days), even if the condition clears and returns meanwhile. After the cool-down it fires again only if the condition is still true. Suppressed repeats are counted and shown in the Alerts page.
- There is no "resolved" notification.
- A failing channel never blocks other channels or other rules: each send has a 15 s timeout and runs in the background (at most 16 at a time). The failure is shown as the rule's last notify error.
- Bounds: at most 25 subjects notify per rule per evaluation, and at most 10,000 subjects are tracked in total, so a flood becomes a bounded number of messages.
- **State lives in memory.** After a restart, every condition that is still true notifies once more, and `events_dropped` takes a new baseline reading.
- Rules are re-read from the database at every tick, so edits apply without a restart.

## Rule kinds

Common fields: `name`, `enabled`, `severity` (`info`, `warning`, `critical`), `cooldown_seconds`, `channel_ids` (at most 10), and the kind's `params`.

| Kind | `params` | Fires when |
| --- | --- | --- |
| `blocks_threshold` | `site_id` (optional, all sites if empty), `threshold` (1 to 10,000,000), `window_seconds` (60 to 86,400) | blocks on a site within the window are **greater than** the threshold |
| `new_country` | `site_id` (optional), `window_seconds`, `baseline_seconds` (each 60 to 86,400) | a country is among the sources of events in the window and was absent in the preceding baseline period. Never fires without a baseline |
| `cert_expiring` | `days` (1 to 365) | a certificate serving a site host expires in fewer than `days` days, or has expired |
| `feed_failure` | none | an enabled feed's last refresh failed |
| `events_dropped` | none | the dropped-event counter increased since the last evaluation (the first reading is only a baseline; a counter that goes down is treated as a restart) |
| `upstream_unhealthy` | `site_id` (optional) | an upstream's last health probe failed |

Example (valid for `PUT /alert-rules/{id}`; `channel_ids` must name existing channels):

<!-- validate:alert:blocks_threshold -->

```json
{
  "name": "Blocks spike on shop",
  "kind": "blocks_threshold",
  "enabled": true,
  "severity": "critical",
  "cooldown_seconds": 900,
  "channel_ids": ["ops-slack"],
  "params": { "site_id": "shop", "threshold": 500, "window_seconds": 300 }
}
```

## Channels

A channel is a named, typed destination. `PUT /notification-channels/{id}` takes `name`, `type`, `enabled`, `settings`. All HTTP channels: HTTPS only unless `allow_http` is `true`; no redirects; 10 s timeout; link-local and metadata addresses refused at connect time; private ranges allowed; unknown settings fields are rejected; errors name the host, never the URL (webhook URLs are credentials and are stored encrypted and masked).

| Type | Settings | Notes |
| --- | --- | --- |
| `webhook` | `url`, `allow_http`, `bearer_token` | Posts JSON with schema `sherlock.alert.v1`: `title`, `body`, `severity`, `rule_id`, `rule_name`, `at`, `fields`. Optional `Authorization: Bearer` header |
| `slack` | `url`, `allow_http` | Slack-compatible incoming webhook (text plus two blocks). `&`, `<` and `>` are escaped so event data cannot create mentions or links |
| `teams` | `url`, `allow_http` | Microsoft Teams Workflows webhook receiving an Adaptive Card (the Office 365 connectors it replaces are retired). Markdown characters in values are backslash-escaped. **Verify against your tenant** that the workflow accepts the card layout |
| `smtp` | `host`, `port`, `security` (`starttls` default, `tls`, `none`), `allow_insecure`, `username`, `password`, `from`, `to` (1 to 20), `timeout_seconds` (1 to 60) | Plain-text mail. `none` needs `allow_insecure: true` and cannot carry credentials; with `starttls` nothing is sent if the server does not offer STARTTLS. TLS 1.2 or newer with certificate verification. CR/LF in addresses and subject are rejected |

<!-- validate:channel:slack -->

```json
{ "url": "https://hooks.slack.com/services/T000/B000/XXXXXXXX" }
```

<!-- validate:channel:smtp -->

```json
{
  "host": "smtp.example.internal",
  "port": 587,
  "security": "starttls",
  "username": "sherlock",
  "password": "app-password",
  "from": "sherlock@example.com",
  "to": ["secops@example.com"]
}
```

A channel that an alert rule still uses cannot be deleted (409 names the rules). A disabled channel is skipped silently. Use the **Test** button on the channel dialog before relying on it.

## Message content policy

Alert messages carry only identifiers and counts: rule id and name, severity, time, site id, country code, host, feed or upstream name, and numbers. They never contain request paths, query strings, headers, bodies, client IP addresses or matched payloads. All text is stripped of control characters and truncated (title 200, body 2,000, up to 20 fields of 256 characters), and channel-specific markup is escaped. Details stay in the dashboard behind authentication.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Alert never fires | rule enabled; at least one channel; `new_country` has a baseline; the Alerts page "last evaluated" is recent; last error column |
| Fires once and never again | working as designed during the cool-down; see "suppressed" count |
| Fires after every restart | state is in memory; the condition is still true |
| Channel test passes, alerts do not arrive | channel enabled; rule lists the channel id; "last notify error" on the rule |
| Many messages at once | up to 25 subjects per rule per evaluation; narrow with `site_id` or lengthen the cool-down |
