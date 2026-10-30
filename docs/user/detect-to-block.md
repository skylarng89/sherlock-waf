# Roll out from detect to block

A WAF that blocks real customers is worse than none. Sherlock lets you start in **detect** mode, see exactly what it *would* have blocked, remove the false positives, and only then switch to **block**, per site and even per endpoint.

| Mode | What happens to a request that scores above the threshold |
| --- | --- |
| `off` | Nothing is inspected |
| `detect` | It is let through and an event records that it would have been blocked |
| `block` | It is answered with the block page and an event is recorded |

## 1. Start in detect and collect evidence

Put the site in `detect` ([first site](first-site.md)). Leave it for long enough to cover your normal traffic: at least one full business cycle (a week is typical), including batch jobs, partner integrations and admin tooling.

## 2. Read the would-block report

The report counts requests a detect-mode site would have blocked for a period, grouped by rule and by path. In the dashboard it is on the site's reports page; through the API:

```sh
curl -s "https://127.0.0.1:9443/api/v1/reports/would-block?site=app&from=2026-10-01T00:00:00Z&to=2026-10-08T00:00:00Z" \
  -H "Authorization: Bearer $SHERLOCK_TOKEN"
curl -s ".../reports/would-block.csv?site=app&from=...&to=..." -H "Authorization: Bearer $SHERLOCK_TOKEN" > would-block.csv
```

Read it from the top:

- **A rule that fires on many paths from many clients** is probably a false positive or an application quirk. Investigate that rule first.
- **A path that dominates the list** (a rich-text editor, a search box, a JSON API that carries code) needs an endpoint-level exception rather than a global change.
- **A few hits from unfamiliar IPs on odd paths** are the attacks you are paying for. Leave them.

Open individual events to see the matched data, the rule description and the anomaly score. Everything shown is data from the request; it is displayed as text, never executed.

## 3. Tune with the smallest change that works

From least to most invasive:

1. **Endpoint override.** Give the one noisy endpoint its own policy, for example a lower paranoia level or a higher threshold:

   ```yaml
   sites:
     - id: app
       policy: { mode: detect, waf: { paranoia_level: 1 } }
       endpoints:
         - id: editor-save
           match: { path: /api/posts, methods: [POST] }
           policy: { waf: { inbound_threshold: 10 } }
   ```
2. **Turn the WAF off for one endpoint** (`policy: { waf: { enabled: false } }`) or skip static file types (`skip_inspection_extensions`), when the traffic cannot be made to fit. Rate limits and access control still apply. Per-rule exclusions are planned for a later release; until then, a higher threshold on the endpoint is the finer tool.
3. **Allow lists** ([access control](access-control.md)) for trusted networks such as your office or a partner; by default an allow list skips rate limits and bot checks, not the WAF.

Apply each change, wait, and look at the report again. Do one change at a time so you know what fixed what. Raising the paranoia level makes the WAF stricter and noisier; raise it only after the report is quiet at the current level.

## 4. Switch to block

When the report for a representative period lists only things you are happy to block:

```yaml
policy: { mode: block }
```

or use the one-click "switch to block" action on the report page. Roll out the safest way:

1. Switch one low-risk site, or one endpoint (`endpoints[].policy.mode: block`), first.
2. Keep `fail_mode: open` unless you must fail closed (it decides what happens if inspection itself fails).
3. Watch the event list and your application's error rate for the next hours. Customer reports of the block page are your signal: the event for that request shows which rule fired.

## 5. Roll back fast

Every configuration change is a version. Switching a site back to detect is a one-line change, and any earlier version can be restored:

```sh
curl -s https://127.0.0.1:9443/api/v1/config/versions -H "Authorization: Bearer $SHERLOCK_TOKEN"
curl -s -X POST https://127.0.0.1:9443/api/v1/config/versions/<id>/rollback -H "Authorization: Bearer $SHERLOCK_TOKEN" -H 'If-Match: "<current etag>"'
```

Rolling back a configuration does not touch your data, certificates or users.

## Keep going

Review the report monthly and after every application release. New features add new request shapes, and a rule that was quiet last quarter can start to fire.
