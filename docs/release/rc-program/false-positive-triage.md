# False-positive triage

How a report that Sherlock blocked or flagged legitimate traffic is handled. The user-facing tuning steps are in [detect to block](../../user/detect-to-block.md#3-tune-with-the-smallest-change-that-works).

## Intake

Each report carries: the event id (`X-Sherlock-Event-Id` on the block page), site, time, what the user was doing, and whether it is repeatable. The event shows the rule ids, matched data (redacted) and anomaly score. Never ask a partner to send raw cardholder data or credentials; the event is enough.

## Classify

| Class | Meaning | Action |
| --- | --- | --- |
| Application quirk | The request really looks like an attack (a rich-text field carrying markup, a search box with SQL words, a JSON API carrying code) | Endpoint-level policy: threshold, or a scoped exclusion; no product change |
| Sherlock false positive | A rule or module blocks a request that is clearly benign and typical | Product fix: a tuned rule, a better exclusion default, or a bug fix; add the request to the benign corpus |
| Misconfiguration | A partner setting caused it (wrong site mode, wrong trusted proxy so the wrong client address, rate limit too low) | Correct the configuration; improve the docs or validation if it was easy to get wrong |
| Real attack | The request is malicious | Leave blocked |
| Bug | Wrong decision unrelated to rules (for example a module error, `sherlock_internal_errors_total`) | Regression ticket, severity by impact |

## Decide the fix, smallest first

1. Endpoint-level change for one path (paranoia level, threshold, WAF off for that endpoint).
2. A scoped exclusion created from the event (rule id and the one target on the one path) rather than a global change.
3. A change in Sherlock (rule tuning, default, or code) when several partners hit the same thing.

Record each decision with the rule id, path pattern, who approved it and the date. A global change needs the program owner's approval.

## Regression tests

A product-side fix is not done until:

- the benign request is added to `test/corpus/benign` (or the known-false-positives file if it cannot be fixed yet), and
- the attack the rule was written for still passes the CRS regression and nuclei suites.

## Tracking

| Field | Value |
| --- | --- |
| Report id | |
| Partner and site | |
| Event id, rule id(s) | |
| Class | |
| Fix and where | |
| Test added | |
| Released in RC | |
| Partner confirmed fixed | |

## Metrics for the exit criteria

Keep counts per partner: reports, classes, time to first response, time to fix, and false positives per million requests during `block` (the partner provides request totals). These feed the [exit criteria](exit-criteria.md).
