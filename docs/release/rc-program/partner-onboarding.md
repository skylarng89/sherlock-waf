# Partner onboarding (week 1)

## Before the call

- [ ] Partner agreement or letter signed: scope, confidentiality, how findings may be used, no warranty, 30-day commitment.
- [ ] Named operator and an escalation contact on both sides, with working hours.
- [ ] Partner's site, upstream address, traffic pattern, peak times, known integrations (webhooks, partners, batch jobs) and release calendar for the next 40 days.
- [ ] Environment decision: where Sherlock runs (VM, container), network path, who owns DNS cutover, how to bypass Sherlock in an emergency (direct DNS or load-balancer switch).

## Day 1: install and detect

1. Install the RC ([install](../../user/install.md)) and verify the release signature ([release process](../release-process.md#verifying-a-release-users)).
2. Create the first administrator, enrol MFA, restrict the control plane and admin listeners to the partner's network.
3. Protect the site in `detect` mode ([first site](../../user/first-site.md)); confirm normal traffic flows and events appear.
4. Configure an exporter to the partner's log store and an alert rule for dropped events and for an unhealthy upstream ([exporters and alerts](../../user/exporters-and-alerts.md)).
5. Record the starting state in the [partner log](partner-log.md): RC version, date, site, mode.

## Days 2 to 7: collect evidence

- Leave the site in `detect` for at least one business cycle (see [detect to block](../../user/detect-to-block.md)).
- Complete the [daily check-in](feedback-templates.md#daily-check-in) each business day.
- Review the would-block report together on day 3 and day 7 and tune ([triage](false-positive-triage.md)).
- Agree the block-mode scope: which site or endpoints go to `block` first, the date and the rollback owner.

## Before switching to block

- [ ] The would-block report for a representative week lists only traffic the partner agrees to block.
- [ ] Rollback tested once: the partner has switched a site to `detect` and back, and restored an earlier config version.
- [ ] Monitoring in place: partner's application error rate and Sherlock's `sherlock_requests_total`, `sherlock_internal_errors_total`, `sherlock_upstream_healthy`.
- [ ] A named person is on call on the first day in `block`.
- [ ] `fail_mode` agreed (see the [runbook](block-mode-runbook.md#fail-mode)).

## What the partner receives

The RC announcement, the runbook, the check-in templates, a direct contact, and the release notes for each new RC with a clear statement of what changed and whether the 30-day count is affected.
