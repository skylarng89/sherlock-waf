# M4 · Dashboard foundation

- Phase: 2 · MVP
- Depends on: M3
- Ships: `v0.2.0`
- Read first: ADR-0008, `docs/architecture/api.md`, `docs/architecture/extension-points.md` (dashboard part), `docs/engineering/coding-standards.md` (TypeScript/Vue), `docs/security/threat-model.md` T6

## Goal

A usable, accessible dashboard for setup, sites, certificates and WAF settings, built only on the public API.

## Tasks

- [ ] **M4-T1** App shell: layout (sidebar, top bar, theme toggle light/dark/system), routing with auth guard, Pinia session store, generated API client wrapper with error handling (problem+json → toasts and field errors), i18n setup, `extensions.ts` registration API.
- [ ] **M4-T2** Design system: Tailwind v4 tokens, OpenVue theme configuration, `Sk*` wrapper components only where needed (page header, empty state, status badge, confirm dialog, form field with error).
- [ ] **M4-T3** Auth pages: login, MFA challenge, MFA enrolment (QR code generated client-side from otpauth URI), logout, session expiry handling.
- [ ] **M4-T4** Setup wizard (`/setup`, only when no users exist): create admin + MFA, set admin hostname (optional ACME), add first site in detect mode with a connectivity test to the upstream.
- [ ] **M4-T5** Sites: list (mode badges, hosts, last-24h block counts placeholder), create/edit forms covering every M1 config field, mode switcher with confirmation for `block`, delete with typed confirmation.
- [ ] **M4-T5b** Global defaults page and site **Endpoints** tab: list endpoints with match and precedence, create/edit override forms that show inherited values greyed with their source and an "override" toggle per field; "Test a request" box (method + path → matched endpoint and effective policy).
- [ ] **M4-T6** Certificates page: ACME status per host, upload certificate (PEM), expiry warnings. Backend: certificate upload API, upstream mTLS client certs (FR-PRX-4), WebSocket/gRPC passthrough options (FR-PRX-6), security headers (FR-PRX-7), custom block page template upload (FR-WAF-9).
- [ ] **M4-T7** Users and API tokens pages; audit log page with filters.
- [ ] **M4-T8** Config history page: list versions, view diff, rollback.
- [ ] **M4-T9** Overview page v0: sites status, requests and blocks (from rollups) as ECharts line chart, CRS and Sherlock version.
- [ ] **M4-T10** Playwright e2e: setup wizard → add site → switch to block → attack request blocked → event visible via API; axe checks on every page.

## Acceptance criteria

1. A new user goes from first launch to a protected site in under 10 minutes using only the dashboard (timed manual test, recorded in the PR).
2. Every page passes axe with no serious or critical violations; full keyboard navigation works.
3. CSP `default-src 'self'` with no `unsafe-inline` scripts; no external network requests from the dashboard (verified in Playwright).
4. Every form shows server validation errors next to the right field.
5. A user can tell, for any field on an endpoint, whether it is inherited and from where, without reading docs (usability check with one design partner).
6. Dark and light themes both readable (contrast ≥ 4.5:1 for text).
