# Exit criteria

The RC program ends, and `v1.0.0` can be cut, when all of these are true.

## Program

- [ ] At least three partners completed 30 days in `block` mode ([definition](README.md#what-counts-as-a-completed-partner-run)), recorded in the [partner log](partner-log.md) with sign-offs.
- [ ] The partners differ in kind (see [selection](README.md#selection)).
- [ ] Every partner returned the end-of-program questionnaire.

## Quality

- [ ] No open blocking regression and no unresolved Level 3 escalation.
- [ ] No unexplained false positive older than 5 business days; every false positive is classified and has a decision ([triage](false-positive-triage.md)).
- [ ] No partner needed a rollback for more than 48 hours in the last 14 days of its run.
- [ ] `sherlock_internal_errors_total` did not increase unexplained during any partner's final 14 days.
- [ ] No event, log or export in any partner environment contained a full card number or a credential (the partners confirm by sampling).
- [ ] The false-positive rate during `block` is at or below `[agreed threshold, per million requests]` for every partner.

## Product

- [ ] Every issue found is fixed, or accepted by the program owner in writing with a reason and a target release.
- [ ] The last RC contains no changes since the version the partners ran, other than fixes the partners confirmed; if it does, the affected partners re-confirm.
- [ ] Upgrade tested from the previous two minors and between the partners' RC versions.

## Other 1.0 criteria (check before tagging)

- [ ] All Phase 3 milestones complete.
- [ ] Penetration test: no open critical or high finding ([findings tracker](../../security/pentest/findings-tracker.md)); summary letter ready.
- [ ] API, config schema v1 and event schema v1 frozen.
- [ ] Release checklist in [release-process](../release-process.md#release-checklist-human-before-tagging) complete.

## Decision

| Field | Value |
| --- | --- |
| Date | `[ ]` |
| Decided by | `[ ]` |
| Final RC | `[v1.0.0-rc.N]` |
| Exceptions accepted | `[ ]` |
