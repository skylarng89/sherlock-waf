# Check-in templates

Short and structured, so results can be compared across partners. Send by the agreed channel; keep the records in the partner's folder.

## Daily check-in

Complete each business day during `detect` and `block`. Two minutes.

| Field | Answer |
| --- | --- |
| Date | |
| Partner and site | |
| Sherlock version (RC) | |
| Mode today (detect / block, which scope) | |
| Anything changed since yesterday (config, Sherlock, application release) | |
| Customer reports of being blocked (count and event ids) | |
| Would-block or block count vs. yesterday (normal / higher / lower) | |
| Application error rate vs. normal | |
| Sherlock alerts fired | |
| Rollback today? (yes/no, reason) | |
| Anything unexpected | |

## Weekly check-in

| Field | Answer |
| --- | --- |
| Week ending | |
| Days in `block` mode so far (count) | |
| False positives found / fixed / still open | |
| Attacks stopped that mattered (examples with event ids) | |
| Missed attacks or bypasses suspected | |
| Incidents (customer impact, rollback) and how they ended | |
| Performance: added latency noticed? resource use? | |
| Operations: upgrades, backups, exporter delivery, alert noise | |
| Documentation or UI problems | |
| What would stop you from recommending Sherlock to a peer | |
| Blockers for the next week | |

## End-of-program questionnaire

| Question | Answer |
| --- | --- |
| Did you complete 30 days in block mode? | |
| Would you run Sherlock in production on this site? | |
| Top three things to fix before 1.0 | |
| Biggest surprise, good or bad | |
| Is there any data you were uncomfortable sharing with us? | |
| May we quote you (name, role, organisation) and in what form? | |

## Incident report

| Field | Answer |
| --- | --- |
| Start and end time (with time zone) | |
| What customers experienced | |
| Event ids involved | |
| Rule ids that fired | |
| Immediate action taken | |
| Config version before and after | |
| Suspected cause | |
