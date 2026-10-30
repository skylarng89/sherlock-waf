# Virtual-patching process

How CVE rules get from "exploited in the wild" to a Sherlock release. Owner: maintainer. Applies from M8.

## Intake (weekly, plus on alerts)

1. A scheduled workflow (`.github/workflows/kev-watch.yml`) fetches the CISA Known Exploited Vulnerabilities JSON feed daily and opens an issue labelled `vpatch-triage` for each new entry whose product or description matches web-facing keywords (web, HTTP, portal, API, CMS, plugin, gateway, VPN web interface, framework names).
2. Other sources reviewed weekly: vendor advisories for common stacks (WordPress plugins, Drupal, Magento, Atlassian, Fortinet/Ivanti/Citrix web portals, Spring, Struts, Log4j-style library issues), CRS project announcements, ProjectDiscovery nuclei template additions.

## Triage (target: 2 business days, 24 h for critical)

Decide one of:

| Outcome | When |
| --- | --- |
| **Covered by CRS** | Reproduce the public exploit against Sherlock at PL1 with CRS only; if blocked, record coverage in the CVE catalogue (`rules/virtual-patches/covered-by-crs.yaml`) so the dashboard can still show it |
| **Write rule** | Not blocked or only at high PL, product used by our audience, exploit details public |
| **Out of scope** | Not reachable over HTTP, desktop/mobile software, no public details, or product irrelevant to users |

## Writing a rule

- Narrowest possible match: specific path(s), method, parameter and payload pattern of the exploit, not just the attack class.
- Rule file `SV-<year>-<n>.conf`, metadata `SV-<year>-<n>.yaml`, ID from the reserved range.
- Tests: a nuclei template (or go-ftw YAML) reproducing the exploit request, and the rule must not fire on the benign corpus or on the product's normal traffic sample if available.
- Severity and `stacks` set so product-specific rules do not activate on unrelated sites.
- Review: second look by a reviewer whose job is to find bypasses (encoding, case, alternative paths, HTTP method override); fix what they find.

## Release

- Critical + actively exploited: emergency patch release (target ≤ 24 h after validation), advisory in release notes and on the dashboard ("New protection: CVE-…").
- Others: next scheduled patch or minor.

## Retirement

Rules stay while the CVE is relevant. After 24 months, review rules with zero hits across opt-in telemetry/design partners; retire only with a changelog note.

## Implementation notes (M8)

- Files per patch in `rules/virtual-patches/`: `SV-<year>-<n>.conf` (SecLang, ids 9,500,000-9,599,999), `SV-<year>-<n>.yaml` (metadata, strict schema in `internal/vpatch`), `SV-<year>-<n>.tests.yaml` (positive exploit requests and benign negatives). `covered-by-crs.yaml` lists CVEs CRS blocks, each with the replayed request.
- `verification`: `synthetic` means the exploit request was rebuilt from public write-ups and tested against Sherlock only; `product-verified` means it was also replayed against a vulnerable instance. The initial pack is all `synthetic`; upgrade a patch only after a real replay.
- `kev: true` is checked by the `verify` job of `.github/workflows/kev-watch.yml` against the CISA catalogue.
- Tests: `go test ./internal/dataplane/waf -run 'EveryVirtualPatch|CoveredByCRS|ProductRules|EveryPatch'` (exploits blocked, benign requests clean, CRS-covered claims still true, zero blocks on the benign corpus with every patch enabled). go-ftw is the CRS suite; patch tests are Go tests because Coraza and the handler are in-process.
- Coraza does not expose multipart file contents, so exploits that hide in an uploaded file (for example CVE-2021-22205) cannot be matched by rule; they stay in the triage backlog.
- Rules read request paths from `REQUEST_FILENAME`. Static-asset skipping (`skip_inspection_extensions`) applies to GET/HEAD without a query string, so an exploit that sends its payload in a header on a `.js` path (ProxyLogon uses `/ecp/x.js`) is not inspected; the pack's own test uses a non-static path. Review that setting for Exchange sites.
