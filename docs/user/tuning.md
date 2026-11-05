# Tuning: false positives, custom rules, paranoia levels and virtual patches

Everything here is configuration (`policy.waf`, `policy.stacks`, `policy.virtual_patches`) and works at global, site and endpoint level. The dashboard and the API write the same fields. Reference: [config-model.md](../architecture/config-model.md).

## Fix a false positive

1. Open the blocked (or would-block) event and ask for an exclusion: `POST /api/v1/sites/{site}/exclusions/propose` with `{"event_id": "..."}`.
2. Sherlock proposes the narrowest exclusion: this rule, this parameter (target), this path, this method. The answer includes how many events of the last 30 days it would have affected (`matching_events`, `no_longer_blocking`) and warnings.
3. Save it with `POST /api/v1/sites/{site}/exclusions` (`If-Match` as for every config change). The next identical request is allowed. The audit log records who added it (`waf.exclusion.create`, with the source event).

Warnings you may see: `whole_category` (the exclusion switches off most rules of an attack class; critical when it applies to every path), `blocking_evaluation` (it removes the rule that decides blocking), `unscoped_rule_removal`, `broad_scope`, `no_matching_events`. A critical warning is refused unless the request sets `acknowledge_warnings: true`.

An exclusion belongs to one site. It never changes what another site detects.

```yaml
policy:
  waf:
    exclusions:
      - id: search-box
        description: Search box triggers SQLi false positive
        match: { paths: ["/search"], methods: [GET] }
        remove_targets: [{ rule_ids: ["942100"], target: "ARGS:q" }]
```

Application packages for WordPress, Django admin and JSON APIs are in `test/corpus/benign/exclusion-packages/`; each is tested to fix real false positives without hiding attacks on the same endpoints.

## Custom rules

`policy.waf.custom_rules` takes SecLang with ids 10000-99999. Check before saving: `POST /sites/{site}/custom-rules/validate`; save with `PUT /sites/{site}/custom-rules`. Rules are compiled in a throwaway engine, and refused when they use directives other than `SecRule`, `SecAction` and `SecMarker`, actions such as `exec`, `allow`, `redirect` or `ctl` other than `ruleRemove*`, file or network operators, the `ENV` variable, or ids outside the range. Each issue names its line.

## Outbound (response) inspection

`policy.waf.outbound_inspection: true` runs the CRS response rules (database errors, stack traces, web shells) on upstream responses of the configured `outbound_content_types`, up to `outbound_max_body_bytes`. In detect mode findings are recorded like inbound ones; in block mode a flagged response is replaced by the block page. Compressed responses are not inspected: Sherlock asks the upstream for uncompressed responses on these sites.

## Paranoia levels

PL1 is the default and suited to most sites; PL2 adds rules that catch more but need tuning; PL3 and PL4 are for high-risk applications and expect many exclusions. To try a higher level safely, set `waf.paranoia_level: 2` and keep `waf.blocking_paranoia_level: 1`: the extra rules run and record findings but do not block. After a few days `GET /sites/{site}/paranoia-impact?target=2` shows how many requests raising the blocking level would additionally block, by rule and path. Then raise `blocking_paranoia_level`.

## CRS rule catalogue

`GET /crs/rules?q=sql&site=shop` lists CRS rules with their descriptions, paranoia level and category, and for a site whether each is `enforcing`, `detect_only`, `inactive`, `disabled` or `partly_excluded`.

## Virtual patches

Sherlock ships rules for actively exploited CVEs that generic rules may miss (`GET /virtual-patches`). A product-specific rule runs only on sites that declare the product with `policy.stacks` (for example `[wordpress, php]`); sites without declared stacks get generic rules only. Switch the pack with `policy.virtual_patches.enabled`, one patch with `PUT /sites/{site}/virtual-patches/{id}`. In detect mode a matching request is logged as would-block.

Each patch lists false-positive notes. Several protect install or admin endpoints that only the product itself uses (for example Confluence setup); turn the patch off while you run that wizard. A patch marked `verification: synthetic` was tested with exploit requests built from public write-ups, not against a vulnerable installation: it is a mitigation, patching the product remains the fix.

## In the dashboard

- **Exclusion from an event.** Open an event in the attack explorer and choose "Create exclusion". The dialog proposes the narrowest exclusion (this parameter of this rule on this path and method), shows how many of the last 30 days' events it would have affected and lists its warnings. A critical warning must be acknowledged with a checkbox before the exclusion can be created. That is at most three clicks: open, acknowledge, create.
- **Tuning tab** (Sites, then a site, then Tuning). Lists the site's exclusions with a delete action, hosts the paranoia level helper (explains PL1 to PL4 and shows the predicted additional blocks, by rule and path, before you save; when the detection level is too low to observe the target it says so and offers to raise it first) and the outbound inspection controls (switch, inspected response bytes, content types).
- **Custom rules tab.** A SecLang editor with live validation. Issues are listed by line, and Save stays disabled until the rules are valid. Press Tab to leave the editor.
- **CRS rules** (sidebar) lists every CRS rule with search, category, paranoia level and direction filters, and the enforcement state per site.
- **Virtual patches** (sidebar) lists CVE rules with product, severity, a known-exploited badge, hits and a per-site switch; the overview shows a "Covered CVEs" tile. Declare a site's stacks and virtual-patch options under its Settings tab.

## Static assets and virtual patches

By default GET and HEAD requests for static asset extensions (`.js`, `.css`, images) without a query string skip inspection. A site that declares a product stack with active virtual patches inspects every request instead, because some exploits (for example ProxyLogon) travel on asset-looking paths with the payload in a cookie. Sites without a declared stack keep the skip.
