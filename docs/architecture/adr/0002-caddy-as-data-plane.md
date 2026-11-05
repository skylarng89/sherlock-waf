# ADR-0002: Caddy as the embedded data plane

- Status: Accepted
- Date: 2026-10-28

## Context

A WAF is first a reverse proxy. Writing a correct, fast, secure HTTP/1.1, HTTP/2, HTTP/3 proxy with automatic TLS is years of work. Other self-hosted WAFs commonly build on NGINX with ModSecurity and Lua, or on a custom engine.

## Decision

Embed Caddy v2 (2.11.x at time of writing; Go 1.26+ required) as a library in the Sherlock binary. Implement Sherlock features as Caddy HTTP handler modules. Disable Caddy's admin endpoint and load configuration in-process with `caddy.Load`.

## Consequences

- Automatic HTTPS (ACME), OCSP stapling, HTTP/3, ECH and graceful reloads come for free.
- Everything is Go: one toolchain, one binary, memory-safe.
- Raw throughput per core is likely below NGINX. Mitigation: performance budgets (NFR-1, NFR-2) measured from M2; if they cannot be met, revisit with data.
- We track Caddy releases closely; Caddy security fixes trigger Sherlock patch releases.

## Alternatives considered

| Option | Why not |
| --- | --- |
| NGINX + ModSecurity v3 (libmodsecurity) | C and Lua, CGO or sidecar process, harder for a solo builder; it is the common approach among existing WAF products, so no differentiation |
| Envoy + Coraza proxy-wasm | Heavy operational footprint for self-hosters; Wasm overhead; C++ core we would not modify |
| Go `net/http/httputil.ReverseProxy` from scratch | We would re-implement TLS automation, HTTP/3, health checks, load balancing |
