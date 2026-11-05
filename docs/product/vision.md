# Product vision

## One line

Sherlock WAF is a self-hosted web application and API firewall that a small security or platform team can install in ten minutes, trust in front of financial applications, and hand to an auditor as evidence.

## Problem

Attacks on web apps and APIs in financial services keep rising, and regulators now expect a WAF: PCI DSS 4.0 requirement 6.4.2 has required an automated solution in front of public-facing web applications since 31 March 2025, one that is kept up to date, generates audit logs, and blocks attacks or raises alerts that are investigated immediately.

Teams that cannot or will not send traffic through a cloud WAF (data residency, latency, cost, regulator preference, air-gapped networks) choose between:

- **Proprietary self-hosted WAFs**: capable detection engines, with features such as geo-blocking and log export in paid tiers.
- **Open-source WAF distributions** built on NGINX, ModSecurity and OWASP CRS with a web UI, some with paid plugins.
- **Raw ModSecurity or Coraza**: powerful but needs an expert to run.

None of them is built around the questions a fintech security lead actually gets asked: *"Show me the WAF was on, current and blocking for the last 90 days," "Send everything to our SIEM," "Protect our open-banking APIs," "Prove nobody quietly changed the rules."*

## Target users

| Persona | Who | What they need from Sherlock |
| --- | --- | --- |
| **Priya, platform engineer** at a 40-person fintech | Runs Kubernetes and a few VMs, no dedicated security team | Install fast, sensible defaults, few false positives, Terraform/GitOps-friendly config |
| **Daniel, security lead** at a regional bank's digital channel | Owns PCI and regulator audits, has a SOC | Evidence, audit trail, SIEM export, change control, on-prem only |
| **Ama, MSP / agency owner** hosting client sites, some in payments | Many small sites | Multi-site management, cheap hardware footprint |
| **Auditor / QSA** (secondary) | Reviews evidence | Clear reports mapping to PCI DSS 6.4.2 and 10.x |

Primary market for the first year: fintechs, payment service providers, SME lenders, credit unions, agencies serving them. Banks come later, once Sherlock has a track record, a pentest report and paid support.

## Product principles

1. **Safe by default.** New sites start in detect-only mode with a "would have blocked" report. Blocking is one click once the user has seen the evidence.
2. **Explainable decisions.** Every block shows which rule fired, on which part of the request, and how to create an exclusion if it is a false positive.
3. **Evidence first.** Every decision and every config change is logged in a form an auditor accepts.
4. **No phone home.** Sherlock works fully offline. Update checks are opt-in.
5. **Reuse proven engines, own the product.** Caddy, Coraza and OWASP CRS do the hard protocol and detection work. Sherlock's value is the policy model, the UX, the evidence and the finance-specific protections.
6. **Protection is free, management at scale is paid.** Every security protection ships in the open-source core. Enterprise sells what organisations pay for: SSO, compliance reporting, tamper-evident audit, clustering, long retention and support. See [editions.md](editions.md).

## Goals for v1.0 (end of Phase 3)

- Protects HTTP(S) sites and JSON APIs against the OWASP Top 10 and OWASP API Top 10 classes covered by CRS, plus rate abuse, bots and credential stuffing.
- False-positive rate on the CRS regression and our own benign-traffic corpus at or below the CRS baseline at paranoia level 1.
- Added latency target: p95 ≤ 5 ms for a typical GET at paranoia level 1 on 2 vCPU (to be calibrated in M2).
- Installs with one command on a fresh Linux VM or with Docker Compose in under 10 minutes.
- Exports events to syslog/CEF, JSON over HTTP and OpenTelemetry.
- Passes an external penetration test of the admin surface.

## Non-goals

- Not a network firewall, IDS or DDoS scrubbing service. Volumetric L3/L4 floods are out of scope; Sherlock handles L7 floods it can see.
- Not a CDN or cache.
- Not a cloud SaaS in v1. Architecture must not prevent a managed offering later.
- No home-grown ML detection engine before v1.0. Revisit with real traffic data.
- No Windows server support.

## Success measures

| Measure | Target by v1.0 |
| --- | --- |
| Design partners running Sherlock on production traffic | 5 |
| Median time from install to first protected site | under 10 minutes |
| Critical vulnerabilities open in Sherlock itself | 0 |
