# M9 · API protection

- Phase: 3 · Competitive and finance-ready
- Depends on: M7
- Ships: `v0.7.0`
- Read first: `docs/architecture/config-model.md` (api, rate_limits keys), `docs/architecture/request-pipeline.md`, `docs/security/threat-model.md` T13

## Goal

First-class protection for JSON APIs and open-banking style endpoints, the main traffic type for fintechs.

## Tasks

- [ ] **M9-T1** OpenAPI upload and storage (3.0 and 3.1), validated on upload; compiled into a fast router + JSON Schema validators at provision time (evaluate `kin-openapi` or `libopenapi` + `santhosh-tekuri/jsonschema`; record choice in an ADR).
- [ ] **M9-T2** `sherlock_api` module: unknown path/method action; parameter and body schema validation action; findings with JSON pointer of the violation; respects site mode.
- [ ] **M9-T3** JWT validation: JWKS fetched by background job with caching and key rotation, RS/ES/EdDSA algorithms only (no `none`, no HS unless a static secret is configured), `exp/nbf/iss/aud` checks, clock skew setting.
- [ ] **M9-T4** Rate-limit keys `jwt:<claim>`, `api_key:<header>`, `header:<name>` (FR-API-3).
- [ ] **M9-T5** mTLS requirement per site/path with uploaded CA; client cert subject available as a rate-limit key.
- [ ] **M9-T6** UI: site API tab (upload spec, see endpoints, per-endpoint violation counts), JWT config forms.
- [ ] **M9-T7** Tests: OWASP crAPI or a sample open-banking mock behind Sherlock; schema violation and BOLA-style probing cases; fuzz the JWT parser.

## Acceptance criteria

1. Requests to undocumented endpoints are blocked when configured; documented ones pass with ≤ 1 ms p95 added validation latency for typical payloads.
2. Expired, wrong-audience, `alg:none` and wrongly signed JWTs are rejected.
3. Per-client-ID rate limiting works using a JWT claim.
4. JWKS URL pointing to an internal metadata address is refused.
