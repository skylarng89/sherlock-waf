# Editions: open source vs Enterprise

## The rule

> **If it protects traffic, it is open source. If it helps an organisation manage, prove or scale protection, it may be Enterprise.**

Apply this rule to every new feature before writing a milestone task. When unsure, it goes in open source; moving a feature from paid to free later is easy, the reverse destroys trust.

## Licensing

| | Open source (`sherlock-waf`) | Enterprise (`sherlock-waf-enterprise`) |
| --- | --- | --- |
| Licence | AGPL-3.0-only | Proprietary commercial licence |
| Source | Public on GitHub | Private; source available to customers on request (optional) |
| Binary | `sherlock` | `sherlock-ee` (core + Enterprise modules) |
| Contributions | Welcome, under the CLA ([../../CLA.md](../../CLA.md)) | Internal only |

## Feature matrix

| Area | Open source | Enterprise adds |
| --- | --- | --- |
| Reverse proxy, TLS, ACME, HTTP/2, HTTP/3 | Yes | |
| OWASP CRS via Coraza, paranoia levels, detect-only mode | Yes | CRS LTS track option |
| Rule exclusions and false-positive tuning UI | Yes | |
| Global, site and per-endpoint policies with inheritance | Yes | Policy templates shared across a fleet, per-team policy ownership |
| Virtual-patching rule pack for exploited CVEs | Yes | Same rules; SLA on emergency releases and early notice |
| Rate limiting, flood protection | Yes (per node) | Cluster-wide shared limits |
| IP reputation, geo-blocking, CrowdSec | Yes | |
| Bot challenge (JS proof-of-work, cookie), Turnstile/hCaptcha | Yes | |
| API protection: OpenAPI validation, JWT checks, per-client limits | Yes | |
| Account-takeover and credential-stuffing protection | Yes | |
| Sensitive-data masking (card numbers, IDs) in responses and logs | Yes | |
| Dashboard, attack explorer, analytics | Yes | |
| Local users, MFA (TOTP), API tokens | Yes | |
| Roles | Admin, Viewer | Custom roles, per-site permissions, teams |
| SSO | | OIDC and SAML, SCIM provisioning |
| Audit log of config changes and logins | Yes (plain, in DB) | Tamper-evident hash chain, signed export, WORM storage targets |
| Event export: syslog/CEF, JSON webhook, OpenTelemetry | Yes | Native Splunk HEC, Microsoft Sentinel, Elastic, QRadar connectors |
| Event store | SQLite / Postgres, 30-day default retention | ClickHouse for high volume, long retention |
| Compliance reporting | | PCI DSS 6.4.2 / 10.x evidence pack, scheduled PDF reports |
| Multi-node | Independent nodes, config via GitOps file | Clustering, central fleet management, HA control plane |
| Updates | Signed releases, manual offline bundle import | Managed offline update mirror for air-gapped sites |
| Support | Community (GitHub Discussions) | SLA-backed support, security advisories 72 h before public |

## Pricing

Enterprise pricing is available on request.
