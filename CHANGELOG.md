# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions: [Semantic Versioning](https://semver.org/). Maintained by release-please from Conventional Commits.

## [Unreleased]

### Added

- Project plan and design documentation.
- False-positive tuning (M8): site-scoped exclusions compiled before CRS, propose-an-exclusion-from-an-event API with past-event impact and category warnings, custom SecLang rules validated in a throwaway engine with a strict allow-list, outbound (response) inspection with body limit and content-type filter, `blocking_paranoia_level` below `paranoia_level` with a predicted-blocks helper, searchable CRS rule catalogue with per-site state.
- Virtual-patch pack (ADR-0013): `rules/virtual-patches/` format, loader before CRS, `policy.stacks` and `policy.virtual_patches`, an initial pack of 20 rules for exploited CVEs with positive and negative tests, `covered-by-crs.yaml`, `GET /virtual-patches`, and the `kev-watch` triage workflow.
