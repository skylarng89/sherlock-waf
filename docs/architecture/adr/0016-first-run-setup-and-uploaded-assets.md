# ADR-0016: First-run setup token and uploaded assets

- Status: Accepted (M4)
- Deciders: owner (delegated: recommended option adopted)

## Context

M4 adds a dashboard setup wizard, certificate upload (including upstream client certificates) and custom block pages. Each needs a decision with security weight:

1. A wizard that creates the first administrator is an unauthenticated endpoint. Left open, whoever reaches a fresh node first becomes its admin.
2. Private keys must be stored, but Caddy loads certificates and upstream client certificates from files, and the node already treats `node.key` as the root of trust.
3. Block pages are operator-supplied HTML that the data plane renders for blocked clients, including attackers.

## Decision

1. **Setup token.** While the node has no users, the server writes a random 160-bit token to `<data-dir>/setup-token` (mode 0600) and logs only the file path. `POST /setup/admin` needs the token, compares it in constant time, accepts it once (it is consumed before the user is created and restored if creation fails), throttles failures process-wide (5 per minute), and answers 409 as soon as any user exists. The token is never logged: logs are shipped to systems the operator may not control, while whoever can read the data directory can already administer the node. The first admin still enrols MFA at first sign-in, like every account. `sherlock user create --admin` remains the alternative.
2. **Certificates.** Uploaded chains are validated (leaf not expired or not yet valid, has DNS names, key matches, no passphrase, RSA at least 2048 bits, supported curves) and the key is re-encoded as PKCS#8 and sealed with XChaCha20-Poly1305 under purpose `certificate_key`. Caddy gets files: `<data-dir>/certs/<id>.crt|.key` (directory 0700, key 0600), written only when content changed, removed on delete. The key is therefore on disk in clear next to `node.key`, which already protects every other secret on the node; this is the same exposure Caddy has for ACME account keys in its own storage. Compiled Caddy JSON contains paths, never key material.
3. **Block pages.** Templates are `html/template` (contextual escaping), at most 64 KiB, rendered once with sample data at upload (a template that fails then is refused), and rendered into a buffer per request so a failure falls back to the built-in page instead of a half-written response. The response keeps `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` whatever the template contains, so a template cannot load scripts or external resources.
4. **References.** Configuration refers to stored objects by id (`tls.cert_id`, `upstreams.tls.client_cert_id`, `block_page.template_id`). Every apply, including rollback, checks they exist (422 with JSON-pointer paths), and the API refuses to delete an object the live configuration uses (409 naming where).

## Consequences

- A fresh node is safe to expose before setup; the cost is one file read for the operator.
- Rolling back to a version that references a deleted certificate fails loudly instead of half-applying.
- Plaintext key files exist on disk; operators with stricter needs should wait for the planned external-secrets integration (Enterprise) or use `tls.mode: file` with their own HSM-backed paths.
