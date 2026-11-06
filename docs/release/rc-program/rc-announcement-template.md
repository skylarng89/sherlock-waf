# RC announcement template

Send to every design partner when a release candidate is cut. Fill the fields in brackets; keep it short.

---

**Subject: Sherlock WAF `[v1.0.0-rc.N]` is available**

Hello `[name]`,

Release candidate `[v1.0.0-rc.N]` is available.

**Download and verify:** `[release URL]`. Verify the signature as described in the [release process](../release-process.md#verifying-a-release-users) before installing. The container image is `ghcr.io/skylarng89/sherlock-waf:[1.0.0-rc.N]`; RCs are never tagged `latest`.

**What changed since `[previous RC]`:**

- `[Fixed: ...]`
- `[Changed: ...]`
- `[Breaking: ... with migration steps]`

**Does this change your 30-day count?** `[No: the changes do not affect traffic you send / Yes: the restart rule applies because ...]`

**Upgrade steps:** `[sherlock update, or redeploy the image; config schema version; migration notes]`. Back up first (`sherlock backup`). Do not combine the upgrade with a mode change.

**Known issues:** `[list, with workarounds]`

**What we need from you:** keep the daily and weekly check-ins, and tell us within `[2]` business days if an upgrade changes behaviour on your site.

**Contacts:** `[triage engineer, address, response times]`. For a suspected vulnerability, follow [SECURITY.md](../../../SECURITY.md) and do not post details publicly.

Thank you,
`[program owner]`

---

## Before sending

- [ ] Release is tagged and marked pre-release; signatures verify.
- [ ] Changelog "Breaking" section reviewed; migration notes written.
- [ ] Upgrade tested from the version the partners run.
- [ ] Partner log updated with the new RC.
