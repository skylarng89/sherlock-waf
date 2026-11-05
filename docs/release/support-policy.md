# Upgrade and support policy

## Community (open source)

| Version | Gets |
| --- | --- |
| Latest minor | All fixes |
| Previous minor | Security fixes for 3 months after the next minor ships |
| Older | None; upgrade |

Upgrades: in place from any of the previous two minors (NFR-12). For larger jumps, upgrade through intermediate minors. Downgrades are not supported after a database migration; restore the automatic pre-upgrade backup instead.

## Enterprise

- Every minor is supported for 12 months.
- Optional LTS minor once per year, supported 24 months, with CRS LTS track.
- Security advisories shared with Enterprise customers up to 72 hours before public disclosure.

## Deprecation

A feature or API field is marked deprecated in release N (changelog + API `Deprecation` header + dashboard notice) and removed no earlier than N+2 minors, and never inside a major version for `/api/v1` after 1.0.

## End of life of dependencies

When Go, Caddy, Coraza or CRS end support for a version Sherlock uses, the next Sherlock minor moves off it.
