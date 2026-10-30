# ADR-0013: Virtual-patching rule pack for exploited CVEs

- Status: Accepted
- Date: 2026-10-28

## Context

OWASP CRS detects attack techniques (SQLi, XSS, RCE, traversal) generically and stops many exploits, but it is not a CVE signature feed. Exploits for specific products (a vulnerable plugin endpoint, a gateway auth bypass, a deserialisation gadget in a framework) often look like valid requests to generic rules. Financial-sector buyers ask "are we protected against CVE-X?" when a new vulnerability is exploited. Other WAF products market CVE coverage.

## Decision

- Maintain a curated **virtual-patching rule pack** in `rules/virtual-patches/`, written in SecLang, loaded into the same Coraza instance before CRS.
- Rule IDs in a reserved Sherlock range (9,500,000–9,599,999); each rule has a metadata file: CVE IDs, product and versions, severity (CVSS), KEV status, references, stacks (for opt-in by declared technology), false-positive notes, and test files.
- Scope: CVEs with confirmed in-the-wild exploitation (CISA KEV and similar) in web-facing software our users run. Not every CVE. Process in `docs/security/virtual-patching-process.md`.
- Ship the pack inside releases (consistent with ADR-0011), versioned `YYYY.MM.N`; emergency patch releases for critical, actively exploited CVEs (target ≤ 24 h after validation).
- Enabled per policy level; product-specific rules activate based on the site's declared `stacks` or `stacks: auto` (generic, low-FP rules only).
- Free in the open-source edition (protection is free).

## Consequences

- Ongoing maintenance load for the maintainer: budget a weekly KEV review; automation opens an issue for each new web-relevant KEV entry.
- Every rule needs a positive test (exploit blocked) and negative test (benign corpus clean), so quality stays high.
- We can reuse or adapt community material only when its licence allows (Apache-2.0, MIT, CC-BY); never copy commercial vendors' signatures.
- Future option: signed out-of-band rule updates without a binary release, if users need faster delivery than patch releases. Would supersede part of ADR-0011.
