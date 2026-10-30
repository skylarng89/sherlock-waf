# Sherlock WAF

**Self-hosted web application and API firewall, built for teams that have to prove their protection to an auditor.**

> Status: pre-alpha. Planning complete; implementation starting at milestone M0. Not for production use yet.

Sherlock puts a reverse proxy with OWASP CRS-based attack detection, rate limiting, bot defence, API schema enforcement and finance-specific protections in front of your web apps and APIs, as a single binary you run on your own servers.

## Why Sherlock

- **Safe rollout**: every site starts in detect mode with a "would have blocked" report before you enforce.
- **Explainable**: each block shows the rule, the request part and a one-click, narrowly scoped exclusion.
- **Evidence-ready**: structured events, full config history and audit log, SIEM export (syslog/CEF, webhooks, OpenTelemetry).
- **Global policies with per-endpoint overrides**: set defaults once, tighten `/login`, relax an upload endpoint, see the effective policy for any path.
- **Virtual patching**: curated rules for actively exploited CVEs, on top of the OWASP Core Rule Set.
- **API-first protection**: OpenAPI validation, JWT checks, per-client rate limits, mTLS.
- **Finance protections**: credential-stuffing defence and card-number masking.
- **No phone home**: works fully offline; signed updates you can verify.

Built on [Caddy](https://caddyserver.com), [Coraza](https://coraza.io) and the [OWASP Core Rule Set](https://coreruleset.org).

## Editions

Sherlock is open source under the **AGPL-3.0**. An Enterprise edition adds SSO, advanced roles, tamper-evident audit, compliance reports, clustering and support. Every protection feature is in the open-source edition. See [docs/product/editions.md](docs/product/editions.md).

## Documentation

Start at [docs/README.md](docs/README.md). Roadmap: [docs/plan/roadmap.md](docs/plan/roadmap.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require signing the [CLA](CLA.md). Security issues: [SECURITY.md](SECURITY.md), never public issues.

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
