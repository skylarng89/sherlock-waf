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
