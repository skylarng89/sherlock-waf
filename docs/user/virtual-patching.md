# Virtual patching

A virtual patch is a narrow rule that blocks the exploit request for a specific, actively exploited vulnerability (a CVE) in front of the product, while you schedule the real fix. Sherlock ships a pack of them inside the binary. They complement the OWASP Core Rule Set (CRS): CRS blocks attack classes such as SQL injection, virtual patches block named exploits that generic rules often miss.

A virtual patch is a mitigation, not a repair. The vulnerable software stays vulnerable: patch it. Use virtual patching to buy time and to protect what you cannot upgrade quickly.

## What is in the pack

The pack covers 19 vulnerabilities in widely deployed, internet-facing products, all listed in the CISA Known Exploited Vulnerabilities (KEV) catalogue when they were added. They include PHPUnit, Drupal, WordPress plugins, Atlassian Confluence, Microsoft Exchange (ProxyLogon and ProxyShell), Oracle WebLogic, VMware vCenter, Fortinet FortiOS, F5 BIG-IP, Citrix NetScaler, Palo Alto PAN-OS, PaperCut, ConnectWise ScreenConnect and ManageEngine. Each patch has a title, the CVEs, the vendor and product, the affected versions, a severity and CVSS score, references, and notes on possible false positives.

Each patch is marked with how it was verified:

| Verification | Meaning |
| --- | --- |
| Synthetic test | The exploit request was rebuilt from public technical write-ups and is blocked in Sherlock's tests. It was **not** replayed against a vulnerable installation of the product. |
| Verified on product | It was also replayed against a vulnerable instance. |

The pack currently ships only synthetic patches. Treat each as a useful mitigation, with the false-positive notes in mind, not as proof that the product is safe.

**Covered by CRS.** For some famous CVEs (Log4Shell, Spring4Shell, Struts, several VPN and gateway bugs) the standard CRS rules already block the exploit at paranoia level 1, so Sherlock does not add a second rule. The catalogue lists these CVEs with the CRS rule ids that block them, and a test replays an example exploit for each so the claim stays true. They show up under "CVEs already covered by CRS" and in the **Covered CVEs** tile on the overview. If your site runs at a lower detection level or has CRS rules excluded, check that the rule is still active.

## When a patch is active

A patch runs on a site only when all of these hold:

1. The pack is on for the site (`policy.virtual_patches.enabled`, default on).
2. The patch id is not in `policy.virtual_patches.disabled` for that site.
3. The site has declared the patch's product in `policy.stacks`.

The third rule keeps a WordPress rule off a site that is not WordPress. Every patch in the current pack is tied to at least one product stack, so **a site with no declared stacks has no virtual patches active**. Declare what the site runs:

```yaml
sites:
  - id: shop
    hosts: [shop.example.com]
    tls: { mode: acme }
    upstreams: { targets: ["10.0.0.5:8080"] }
    policy:
      mode: block
      stacks: [wordpress, php]                 # activates the WordPress and PHP patches
      virtual_patches:
        disabled: [SV-2019-0002]               # switch one patch off for this site
```

Stack names are lower-case words such as `wordpress`, `php`, `drupal`, `exchange`, `confluence`, `fortinet`, `f5`, `citrix`, `paloalto`. The dashboard offers the names the pack uses; the API lists them as `known_stacks`. Setting `stacks: [auto]` means "none declared".

Settings inherit like the rest of a policy (global, site, endpoint). Lists of disabled patches are combined across levels, so a site cannot re-enable a patch that the global defaults disabled by editing its own list; to drop an inherited entry, name it in `opt_out` as `virtual_patches:<id>`. Declaring stacks at the global defaults makes them apply to every site.

### Static assets

Normally GET and HEAD requests for static files (`.js`, `.css`, images) without a query string skip inspection to save work. A site that declares a stack with active virtual patches inspects every request instead, because some exploits (ProxyLogon is one) travel on a request path that looks like a static file. Sites without declared stacks keep the skip.

## In the dashboard

**Virtual patches** in the sidebar lists the catalogue: patch, CVE, product, severity, the stacks that activate it, a Known exploited badge, its verification level, its hits over the last days, and per site its state:

| State | Meaning |
| --- | --- |
| Active | The patch runs on that site. |
| Stack not declared | The site has not declared the product. Declare the stack in the site policy. |
| Disabled | Switched off for the site. |
| Pack off | Virtual patching is off for the site. |

Search by CVE, product or title, filter by severity or known-exploited, and open a row for the false-positive notes and references. With permission to change configuration you can switch a patch on or off for a site directly from the row. Declare a site's stacks and the pack switch under the site's **Settings** tab. The overview's **Covered CVEs** tile summarises how many CVEs are covered by Sherlock patches and by CRS, how many are known exploited and how many sites are protected.

## API

| Request | Use |
| --- | --- |
| `GET /virtual-patches` | The catalogue with per-site state and recent hits, plus the CVEs CRS covers. Filters: `q` (patch id, CVE, product, vendor or title), `site`, `severity`, `kev`, `days` (1 to 90, default 30, the window for hit counts). Needs `config:read`. |
| `PUT /sites/{site}/virtual-patches/{patch}` with `{"enabled": true\|false}` | Adds or removes the patch from the site's `policy.virtual_patches.disabled`. Needs `config:write` and an `If-Match` header with the configuration ETag. Audited as `virtual_patches.enabled` or `virtual_patches.disabled`. |

Hit counts come from a capped scan of recent events; the response says so (`truncated`) when the cap was reached.

## What a hit looks like

A blocked request appears in the attack explorer like any WAF event, with a rule id in the virtual-patch range (9,500,000 to 9,599,999) and the patch message. In **detect** mode a match is logged as would-block and the request goes through; in **block** mode it is refused. Roll patches out the same way as other protections: watch them in detect mode first ([detect to block](detect-to-block.md)).

Several patches protect setup or administration endpoints that only the product itself uses, for example the Confluence setup wizard or the PaperCut setup page. If you are running such a wizard or legitimately use that endpoint, switch the patch off for the site for the duration and switch it on again afterwards. Each patch's false-positive notes say what to expect. Virtual patches cannot be removed with a rule exclusion (the configuration refuses it); the only switch is `virtual_patches.disabled`, which turns the whole patch off for the site. Exclusions are for CRS rules ([tuning](tuning.md)).

## How the pack is updated

The pack is embedded in the Sherlock binary. Nothing is downloaded at run time, and a node never fetches rules from the network. New and changed patches arrive with a Sherlock release: update with `sherlock update` ([upgrade](upgrade.md)) or install the new package. The pack version is shown on the Virtual patches page.

Behind the scenes, a scheduled job watches the CISA KEV feed for newly exploited web-facing products and opens a triage issue. Each one is classified as already covered by CRS, needing a new rule, or out of scope. A new rule is written as narrowly as possible, tested against the exploit request and against Sherlock's benign traffic corpus, and reviewed by someone looking for bypasses. A critical vulnerability that is being actively exploited is targeted for an emergency patch release within 24 hours of the rule being validated; other rules ship in the next scheduled release. See [the virtual-patching process](../security/virtual-patching-process.md). Patches are retired only with a changelog note.

## Limits

- **Not a substitute for patching.** A rule matches the known exploit request. A variation the rule does not match, or a different exploit for the same flaw, gets through.
- **Synthetic verification.** See above: a patch has not necessarily been replayed against the real product.
- **Request-level only.** Sherlock inspects HTTP requests it proxies. It cannot protect a vulnerable service that clients reach another way, and exploits hidden in the contents of an uploaded file are not matched, because the engine does not expose multipart file contents to rules.
- **Needs stacks.** No declared stack, no product-specific patch.
- **Coverage is small and curated.** It targets a short list of known-exploited, internet-facing products, not every CVE. Keep your own patch process.
