# ADR-0009: AGPL open core with public extension interfaces

- Status: Accepted
- Date: 2026-10-28

## Decision

- Core licensed AGPL-3.0-only. Contributions require signing the CLA so the project owner can also distribute contributed code under the commercial licence.
- Enterprise features live in a private repository and plug in only through `pkg/extension` (see `docs/architecture/extension-points.md`).
- Feature placement rule: protection is free; management, evidence and scale may be paid (`docs/product/editions.md`).

## Consequences

AGPL discourages cloud providers from offering Sherlock as a closed service. Some companies' policies forbid AGPL; the commercial licence covers them. The extension interfaces become a public contract we must version carefully.
