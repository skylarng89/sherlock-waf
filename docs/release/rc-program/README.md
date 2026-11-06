# Release candidate program

Goal: before `v1.0.0`, **at least three design partners run a release candidate in `block` mode for 30 days** ([1.0 criteria](../versioning.md#10-criteria)), and what they find is fixed or consciously accepted. This directory is the operating manual for that program. It follows the usual release rules in [release-process](../release-process.md): an RC is tagged `v1.0.0-rc.N`, is marked as a pre-release, and gets no `latest` image tag.

## What counts as a completed partner run

All of these, for one partner:

1. A production or production-like site protected by one RC (or successive RCs without a break longer than 48 hours) in `mode: block`.
2. 30 consecutive days in `block` mode, counted from the day the partner's agreed scope reached `block` ([runbook](block-mode-runbook.md)). Days spent in `detect` do not count.
3. Daily and weekly check-ins completed ([templates](feedback-templates.md)); every false positive triaged ([triage](false-positive-triage.md)).
4. The [exit criteria](exit-criteria.md) met and the partner's sign-off recorded in the [partner log](partner-log.md).

If a rollback to `detect` lasts more than 48 hours, or a blocking regression is fixed by a new RC, the 30-day count for that partner restarts unless the change is judged not to affect the partner's traffic and both sides agree in writing.

## Roles

| Role | Does |
| --- | --- |
| Program owner (Sherlock) | Selects partners, keeps the partner log, runs the weekly review, decides on the RC cut |
| Partner contact | Operates the deployment, files the check-ins, signs off |
| Triage engineer (Sherlock) | Answers within the response times below, owns false-positive and regression fixes |

## Response times

| Event | Sherlock responds within |
| --- | --- |
| Blocking regression (legitimate traffic blocked, or an outage attributed to Sherlock) | 4 business hours; fix or mitigation advice the same day |
| False positive without business impact | 2 business days |
| Security issue | Per [SECURITY.md](../../../SECURITY.md) |
| Question | 2 business days |

## Selection

Choose partners that differ: a payment or banking API, a consumer web app with logins, a back-office or partner-facing portal, and at least one on PostgreSQL if supported. Each partner needs: a named operator, a staging or low-risk production site to start with, access to their upstream logs, and agreement to share findings. Do not accept a partner whose only traffic is trivial.

## Documents

| Document | Purpose |
| --- | --- |
| [rc-announcement-template.md](rc-announcement-template.md) | What to send when an RC is cut |
| [partner-onboarding.md](partner-onboarding.md) | The first week |
| [block-mode-runbook.md](block-mode-runbook.md) | Shadow to block, rollback, escalation |
| [feedback-templates.md](feedback-templates.md) | Daily and weekly check-ins |
| [false-positive-triage.md](false-positive-triage.md) | How reports are handled |
| [exit-criteria.md](exit-criteria.md) | When the program is done |
| [partner-log.md](partner-log.md) | The scoreboard |

## Weekly rhythm

Monday: review last week's check-ins and open false positives. Wednesday: decide whether an RC is needed. Friday: update the partner log and send partners a short status. The program owner reports the count of partners that have completed 30 days against the target of three.
