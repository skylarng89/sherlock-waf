# Sherlock WAF documentation

This folder is the single source of truth for what Sherlock WAF is, how it is built, and in what order. Code follows these documents. When the code and a document disagree, fix one of them in the same pull request.

Written: 2026-10-28. Status: approved plan, pre-implementation.

## Reading order

| # | Document | Read it when |
| --- | --- | --- |
| 1 | [product/vision.md](product/vision.md) | First. What we are building, for whom, and what we will not build |
| 2 | [product/editions.md](product/editions.md) | Deciding whether a feature belongs in the open-source core or Enterprise |
| 3 | [product/requirements.md](product/requirements.md) | Writing or reviewing any feature. Every requirement has an ID |
| 4 | [architecture/overview.md](architecture/overview.md) | Before touching code. Components, request lifecycle, deployment |
| 5 | [architecture/request-pipeline.md](architecture/request-pipeline.md) | Working on any data-plane module |
| 6 | [architecture/config-model.md](architecture/config-model.md) | Working on configuration, API or dashboard forms |
| 7 | [architecture/api.md](architecture/api.md) | Working on the control-plane API or the dashboard |
| 8 | [architecture/data-model.md](architecture/data-model.md) | Working on storage or migrations |
| 9 | [architecture/events.md](architecture/events.md) | Working on logging, the attack explorer or exporters |
| 10 | [architecture/extension-points.md](architecture/extension-points.md) | Anything Enterprise needs to plug into |
| 11 | [architecture/adr/](architecture/adr/) | Understanding why a decision was made, or proposing to change one |
| 12 | [security/threat-model.md](security/threat-model.md) | Any change to auth, the admin surface, parsing or updates |
| 13 | [security/secure-development.md](security/secure-development.md) | Every pull request |
| 13b | [security/virtual-patching-process.md](security/virtual-patching-process.md) | Adding protection for an exploited CVE |
| 13c | [security/asvs-review-m7.md](security/asvs-review-m7.md) | Auditing the control plane; open security findings and tickets |
| 14 | [engineering/](engineering/) | Repo layout, coding standards, testing, CI/CD, dev environment |
| 15 | [release/](release/) | Versioning, releases, upgrades and support |
| 16 | [operations/deployment.md](operations/deployment.md) | Installing and running Sherlock |
| 16b | [user/](user/) | Install, first site, detect-to-block rollout, backup and restore, upgrade |
| 17 | [plan/roadmap.md](plan/roadmap.md) | Choosing the next milestone |
| 18 | [plan/milestones/](plan/milestones/) | Building. One file per milestone with tasks and acceptance criteria |

## Conventions used in these documents

- **MUST / SHOULD / MAY** follow RFC 2119 meanings.
- Requirement IDs: `FR-<area>-<n>` (functional) and `NFR-<n>` (non-functional). Milestone tasks reference them.
- ADR IDs: `ADR-0001` and up. ADRs are never edited after acceptance except to mark them superseded.
- Version numbers quoted here are the latest stable releases on 2026-10-28. Pin exact versions in M0 and update them through Renovate, not by editing these docs.

## Companion repository

Enterprise features live in the private `sherlock-waf-enterprise` repository. It imports this repository as a Go module and registers extra modules through the interfaces in [architecture/extension-points.md](architecture/extension-points.md). Nothing in this repository may import Enterprise code.
