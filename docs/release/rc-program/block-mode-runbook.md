# Block-mode runbook

The path from detect to block for a partner site, how to roll back, and when to escalate. The mechanics are in [detect to block](../../user/detect-to-block.md); this page adds the program's rules.

## Path

| Step | Action | Gate to the next step |
| --- | --- | --- |
| 1 | Site in `detect` for at least one business cycle | Would-block report reviewed with the partner |
| 2 | Tune false positives with the smallest change that works | Report quiet for 3 consecutive business days at the current paranoia level |
| 3 | Switch one low-risk endpoint or the least critical site to `block` | 48 hours without a blocking regression |
| 4 | Widen the scope in steps, one change at a time, keeping `detect` on the rest | Each step watched for 24 hours |
| 5 | Whole agreed scope in `block`. **Day 1 of the 30-day count** | Daily check-ins |
| 6 | Day 30 | [Exit criteria](exit-criteria.md) |

Do not combine a mode change with a Sherlock upgrade, a paranoia-level change or an application release on the same day.

## Fail mode

Choose per site and record it in the partner log:

- `fail_mode: open` while the partner is new to block mode: an engine error lets the request through.
- `fail_mode: closed` once the partner is comfortable, and always where the site is in PCI scope: an engine error answers 503.

See [failure modes](../../operations/failure-modes.md) for what each does.

## Watch list during block mode

| Signal | Source | Act when |
| --- | --- | --- |
| Customers reporting the block page | Partner support | Any report: find the event by its id (`X-Sherlock-Event-Id`) |
| Application error rate and conversion | Partner monitoring | A change that coincides with a mode or config change |
| `sherlock_internal_errors_total` increasing | Metrics | Any increase: open a regression ticket |
| `sherlock_events_dropped_total`, exporter drops | Metrics | Any sustained increase |
| `sherlock_upstream_healthy` = 0 | Metrics, alert | Confirm origin health first; it is not a Sherlock fault by default |
| Block rate per site (`sherlock_requests_total{action="block"}`) | Metrics | A step change not explained by an attack |

## Roll back

Fastest first, each is an ordinary configuration change and is audited:

1. **One endpoint**: give it its own policy in `detect` (`endpoints[].policy.mode: detect`).
2. **One site**: `policy.mode: detect` ([guide](../../user/detect-to-block.md#5-roll-back-fast)).
3. **Restore a version**: `POST /api/v1/config/versions/{id}/rollback` with `If-Match` set to the current ETag.
4. **Bypass Sherlock**: the partner's pre-agreed path (DNS or load-balancer switch). Use when Sherlock itself is unavailable.

After any rollback, write down the time, the reason and the event ids. If the site was out of `block` for more than 48 hours, see the [restart rule](README.md#what-counts-as-a-completed-partner-run).

## Escalate

| Level | Condition | Who |
| --- | --- | --- |
| 1 | A false positive that the partner can tune around | Partner operator, triage engineer within 2 business days |
| 2 | Legitimate traffic blocked with business impact, or a regression suspected | Triage engineer within 4 business hours; partner rolls back first, investigates second |
| 3 | Outage attributed to Sherlock, data exposure suspicion, or a suspected vulnerability | Program owner and security contact immediately; follow [SECURITY.md](../../../SECURITY.md) for vulnerabilities |

Rollback comes before diagnosis whenever customers are affected.
