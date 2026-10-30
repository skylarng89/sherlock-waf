# M8 · False-positive tuning and rule management

- Phase: 3 · Competitive and finance-ready
- Depends on: M7
- Ships: `v0.6.0`
- Read first: ADR-0013, `docs/security/virtual-patching-process.md`, `docs/architecture/config-model.md` (waf.exclusions, custom_rules, policy inheritance), `docs/security/threat-model.md` T2, T9

## Goal

Make false positives quick and safe to fix, which is where most WAF deployments fail, and add targeted protection for actively exploited CVEs (virtual patching).

## Tasks

- [ ] **M8-T1** Exclusion model and compiler: remove rule by ID/tag for a scope (site, path glob, method), remove target from rule (`ctl:ruleRemoveTargetById`), generated as CRS-style runtime exclusion rules before CRS includes; golden tests.
- [ ] **M8-T2** "Create exclusion from event" API and wizard: proposes the narrowest exclusion (this rule, this target, this path, this method), shows how many past events it would have affected, and warns when it would disable a whole attack category.
- [ ] **M8-T3** Custom rules editor (per site): SecLang with syntax highlighting (CodeMirror 6), validation by compiling in a throwaway Coraza instance, forbidden directives/actions (T9) rejected with clear messages, rule ID range 10000–99999 reserved for users.
- [ ] **M8-T4** Outbound inspection toggle (FR-WAF-8) with response body limit and content-type filter; findings appear like inbound ones.
- [ ] **M8-T5** Paranoia level helper: UI explains PL1–PL4 and shows the would-block delta of raising the level using stored detect-only findings (requires recording findings above blocking PL with `log` action: compile `blocking_paranoia_level` < `paranoia_level` support).
- [ ] **M8-T6** CRS info: list of rules with descriptions (generated from CRS files at build time), search, per-site enabled/disabled state.
- [ ] **M8-T6b** Virtual-patching framework (FR-VP, ADR-0013): `rules/virtual-patches/` format (rule + metadata), reserved ID range, loader into Coraza before CRS, `stacks` declaration on sites (`policy.stacks`) and activation logic, `virtual_patches` policy field (enabled, disabled list) at all three levels.
- [ ] **M8-T6c** Initial pack: 15–25 rules for high-profile, actively exploited web CVEs relevant to target users, each with metadata, nuclei/go-ftw positive test and benign negative test; `covered-by-crs.yaml` for CVEs CRS already blocks.
- [ ] **M8-T6d** `kev-watch.yml` workflow opening triage issues from the CISA KEV feed; `docs/security/virtual-patching-process.md` followed for the initial pack.
- [ ] **M8-T6e** UI: Virtual patches page (catalogue with CVE, product, severity, KEV badge, state per site, hits), site/endpoint toggles, "Covered CVEs" summary on overview; API `GET /virtual-patches`.
- [ ] **M8-T7** Tests: go-ftw still passes with sample exclusions; benign corpus extended with app-specific samples (WordPress, Django admin, JSON APIs) and their exclusion packages documented.

## Acceptance criteria

1. From an event to a working exclusion in ≤ 3 clicks; the next identical request is allowed and an audit entry records who added it.
2. Malicious custom rules (e.g. `exec`, Lua) are rejected.
3. Raising PL from 1 to 2 shows the predicted additional blocks before saving.
4. Every virtual patch blocks its exploit test and causes zero blocks on the benign corpus; a product-specific rule does not activate on a site that has not declared (or auto-detected) that stack.
5. CRS regression suite unaffected by exclusions on other sites (exclusions are site-scoped).
