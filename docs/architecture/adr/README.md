# Architecture Decision Records

We record significant decisions as ADRs (Michael Nygard format). An ADR is immutable once accepted; to change a decision, write a new ADR that supersedes it and update the old one's status line only.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-caddy-as-data-plane.md) | Caddy as the embedded data plane | Accepted |
| [0003](0003-coraza-and-crs.md) | Coraza v3 and OWASP CRS 4, own Caddy handler | Accepted |
| [0004](0004-go-single-binary.md) | Go, single static binary | Accepted |
| [0005](0005-own-config-model.md) | Sherlock-owned config model compiled to Caddy JSON | Accepted |
| [0006](0006-storage.md) | SQLite by default, Postgres optional | Accepted |
| [0007](0007-event-pipeline.md) | In-process bounded event bus | Accepted |
| [0008](0008-dashboard-stack.md) | Dashboard stack | Accepted |
| [0009](0009-open-core-extension-model.md) | AGPL open core with public extension interfaces | Accepted |
| [0010](0010-repositories.md) | Public monorepo plus private Enterprise repo | Accepted |
| [0011](0011-rule-updates.md) | CRS ships inside releases | Accepted |
| [0012](0012-policy-hierarchy.md) | Global, site and endpoint policy hierarchy | Accepted |
| [0013](0013-virtual-patching-rule-pack.md) | Virtual-patching rule pack for exploited CVEs | Accepted |

New ADRs: copy [template.md](template.md), take the next number, open a PR titled `docs(adr): NNNN <title>`.
