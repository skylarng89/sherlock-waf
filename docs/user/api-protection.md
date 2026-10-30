# API protection

Sherlock can check requests to a JSON API against its OpenAPI document, validate bearer tokens, require client certificates and rate-limit per caller instead of per address. Everything is under `policy.api` (site or endpoint level) and in the dashboard under **Sites → API**.

In `detect` mode every block action only records a finding; switch the site to `block` to enforce.

## OpenAPI conformance

1. Upload a document (OpenAPI 3.0 or 3.1, JSON or YAML, up to 4 MiB): dashboard **Sites → API → Upload**, or `PUT /api-docs/{id}` with `{"name": "...", "content": "<document text>"}`. A document that does not parse or validate is refused with the reason and the previous version stays live. References to other files or URLs are not followed, so inline everything with `$ref: '#/components/...'` only.
2. Select it on the site (`openapi_doc_id`) and set the actions:
   - `unknown_path_action`: the path or method is not in the document.
   - `schema_violation_action`: a path, query or header parameter or the JSON body breaks the schema.

Findings carry a JSON pointer such as `/body/amount`, `/query/currency` or `/path/id`. Messages never contain the offending value. Bodies above `max_body_bytes` (default 1 MiB) are passed on without validation and a notice is logged.

The endpoints table in the dashboard shows schema violations per documented endpoint for the last 24 hours, and a list of requests to undocumented paths or methods.

## Tokens (JWT)

```yaml
policy:
  api:
    enabled: true
    jwt:
      - match: { paths: ["/api/*"] }
        jwks_url: https://auth.example.com/.well-known/jwks.json
        issuer: https://auth.example.com/
        audiences: [shop-api]
```

- Accepted algorithms: RS, PS, ES (256/384/512) and EdDSA. `none` is never accepted. HS256/384/512 are accepted only for a rule with `hmac_secret_env` (an environment variable of at least 32 bytes).
- `exp` is required. `nbf`, `iss` and `aud` are checked; `clock_skew` (default 30 s, up to 5 m) forgives small clock differences.
- A JWKS is fetched by a background job every `refresh_interval` (default 15 m) and early when a token carries an unknown `kid`, so key rotation needs no reload. The URL must be https; loopback, private, link-local and cloud-metadata addresses are refused. If a refresh fails the previous keys stay in use.
- Instead of a JWKS you can give `public_key_pem`.
- `optional: true` lets requests without a token through; a token that is sent must still be valid. `action: log` records failures without rejecting.
- Rejected requests get `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

## Rate limits per caller

```yaml
rate_limits:
  - { name: per-client, key: "jwt:client_id", limit: 100, window: 1m }
  - { name: per-key, key: "api_key:X-Api-Key", limit: 60, window: 1m }
  - { name: per-tpp, key: "mtls_subject", limit: 300, window: 1m }
```

Only claims of a token that passed validation are used. A request without a usable identity is counted per client address.

## Mutual TLS

1. Upload the CA certificates (PEM, certificates only): **Sites → API → Upload a CA bundle** or `POST /ca-bundles`.
2. Set `mtls.ca_cert_id` and `mtls.required_paths` (for example `["/open-banking/*"]`). The site asks every client for a certificate and verifies one that is offered against the bundle; the listed paths answer `403` without a verified certificate. A client that presents a certificate the CA did not sign fails the TLS handshake.

The certificate subject is available as the rate-limit key `mtls_subject`.

Design background and trade-offs: [ADR-0018](../architecture/adr/0018-api-protection.md).
