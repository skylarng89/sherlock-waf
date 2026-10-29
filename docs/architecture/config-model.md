# Configuration model

Sherlock owns its configuration model (ADR-0005). Users never write Caddy config. The same model is:

- stored in the config store (as normalised rows plus a canonical JSON snapshot per version),
- exposed by the API as JSON,
- exported/imported as YAML for GitOps (`sherlock config export|import|apply`),
- compiled into Caddy JSON by `internal/compiler`.

The Go structs in `internal/config` are the source of truth. A JSON Schema is generated from them (`make schema` → `docs/reference/config.schema.json`) and used by the dashboard for form validation and by editors for YAML autocompletion.

## Versioning

- Top-level `schema_version` (integer). Starts at `1`. Any breaking change increments it and ships a migration function `migrate_N_to_N+1` in `internal/config/migrate`. Import accepts any older version and migrates it.
- Additive changes (new optional fields with defaults) do not bump the version.

## Full example

```yaml
schema_version: 1

global:
  admin:
    listen: "0.0.0.0:9443"          # control plane, separate from proxied traffic
    tls: auto                        # auto (self-signed until a hostname is set) | acme | file
    hostname: waf-admin.example.com
    allowed_cidrs: ["10.0.0.0/8"]   # empty = any
  trusted_proxies: ["10.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
  acme:
    email: ops@example.com
    ca: https://acme-v02.api.letsencrypt.org/directory
  events:
    retention_days: 30
    access_log: { enabled: false, sample_rate: 0.01 }
  feeds:
    geoip: { provider: dbip-lite, auto_update: false }
    reputation_lists: [firehol_level1, spamhaus_drop]
    crowdsec: { enabled: false, lapi_url: "", api_key_secret: crowdsec_key }
  ip_lists:
    - name: office
      cidrs: ["203.0.113.0/24"]
    - name: known-bad
      cidrs: ["198.51.100.7/32"]

sites:
  - id: shop                         # stable slug, immutable after creation
    name: Shop frontend
    hosts: ["shop.example.com", "www.shop.example.com"]
    path_prefix: ""                  # optional
    mode: detect                     # off | detect | block
    fail_mode: open                  # open | closed
    tls:
      mode: acme                     # acme | file | none (HTTP only, discouraged)
      cert_id: ""                    # for mode=file, references an uploaded cert (M3+)
      cert_file: ""                  # file config only: PEM path for mode=file
      key_file: ""                   # file config only: PEM key path for mode=file
      min_version: "1.2"
      hsts: { enabled: true, max_age: 31536000, include_subdomains: false }
    upstreams:
      targets: ["10.0.1.10:8080", "10.0.1.11:8080"]
      lb_policy: round_robin         # round_robin | least_conn | ip_hash
      health_check: { path: /healthz, interval: 10s, timeout: 2s }
      tls: { enabled: false, insecure_skip_verify: false, client_cert_id: "" }
      timeouts: { dial: 5s, read: 60s, write: 60s }
    headers:
      security_headers: true
      custom_response: { "X-Frame-Options": "DENY" }
    waf:
      enabled: true
      paranoia_level: 1
      blocking_paranoia_level: 1
      inbound_threshold: 5
      outbound_threshold: 4
      outbound_inspection: false
      max_body_bytes: 10485760
      skip_inspection_extensions: [".css", ".js", ".png", ".jpg", ".svg", ".woff2"]
      exclusions:
        - id: excl-01
          description: "Search box triggers SQLi FP"
          match: { paths: ["/search"], methods: ["GET"] }
          remove_rule_ids: []
          remove_tags: []
          remove_targets: [{ rule_ids: ["942100"], target: "ARGS:q" }]
      custom_rules: |
        SecRule REQUEST_URI "@beginsWith /admin" "id:10001,phase:1,deny,status:403,msg:'Admin path blocked'"
    acl:
      allow_lists: [office]
      deny_lists: [known-bad]
      countries: { mode: deny, list: ["KP"] }   # allow | deny | off
      reputation: { enabled: true, action: block }
      password_gate: { enabled: false, username: "", password_hash: "" }
    rate_limits:
      - name: global-per-ip
        match: { paths: ["/*"] }
        key: ip                      # ip | header:<name> | jwt:<claim> | api_key:<header>
        limit: 300
        window: 1m
        action: block                # block | challenge | log
      - name: login
        match: { paths: ["/api/login"], methods: ["POST"] }
        key: ip
        limit: 10
        window: 1m
        action: challenge
    auto_ban:
      enabled: true
      blocks_threshold: 20
      window: 5m
      ban_duration: 30m
    bot:
      enabled: true
      challenge: pow                 # pow | turnstile | hcaptcha
      difficulty: 4
      rules:
        - match: { paths: ["/checkout/*"], reputation_below: 50 }
          action: challenge
      verified_bots: allow           # allow | challenge | block
    api:
      enabled: false
      openapi_doc_id: ""
      unknown_path_action: log       # log | block
      schema_violation_action: log
      jwt:
        - match: { paths: ["/api/*"] }
          jwks_url: https://auth.example.com/.well-known/jwks.json
          issuer: https://auth.example.com/
          audiences: ["shop-api"]
      mtls: { required_paths: [], ca_cert_id: "" }
    login_protection:
      enabled: false
      endpoints:
        - path: /api/login
          method: POST
          username_field: email      # JSON pointer or form field
          failure_statuses: [401, 403]
      thresholds: { per_ip: 20, per_username: 5, window: 10m }
      action: challenge
    dlp:
      enabled: false
      detect: [pan]                  # pan | iban | custom:<name>
      custom_patterns: []
      action: mask                   # mask | block | log
    block_page: { template_id: default }
```

## Policy inheritance: global → site → endpoint

Protection settings live in a **policy block**. The same block type appears at three levels:

```yaml
global:
  defaults:                      # policy block applied to every site
    mode: detect
    waf: { paranoia_level: 1, inbound_threshold: 5 }
    virtual_patches: { enabled: true }   # stacks are declared with policy.stacks (unset = auto: generic patches only)
    rate_limits:
      - name: global-per-ip
        match: { paths: ["/*"] }
        key: ip
        limit: 600
        window: 1m
        action: block

sites:
  - id: shop
    hosts: ["shop.example.com"]
    policy:                      # site-level overrides (the protection fields shown in the full example above live here)
      mode: block
      stacks: [wordpress, php]  # declared technologies, used by virtual patches
    endpoints:                   # endpoint-level overrides
      - id: login
        match: { path: "/wp-login.php", methods: ["POST"] }
        policy:
          waf: { paranoia_level: 2 }
          rate_limits:
            - name: login-per-ip
              key: ip
              limit: 10
              window: 1m
              action: challenge
          bot: { enabled: true, challenge: pow }
      - id: uploads
        match: { path_prefix: "/wp-json/wp/v2/media", methods: ["POST"] }
        policy:
          waf: { max_body_bytes: 52428800 }
      - id: healthcheck
        match: { path: "/healthz" }
        policy:
          mode: off
          opt_out: [ "rate_limits:global-per-ip" ]   # explicit opt-out of a global item (audited)
```

**Merge rules** (implemented once in `internal/config/effective.go` and used by compiler, API and UI):

| Field kind | Behaviour |
| --- | --- |
| Scalars (mode, paranoia level, thresholds, limits) | Lowest level that sets it wins |
| Objects (`waf`, `bot`, `api`, `dlp`, …) | Merged field by field |
| Named lists (`rate_limits`, `exclusions`, `virtual_patches.disabled`) | Union by `name`/`id`; a lower level can replace an item with the same name; a global item is removed only through `opt_out` |
| Lists of values (`allow_lists`, `deny_lists`, `stacks`) | Lower level replaces the whole list unless written as `{add: [...], remove: [...]}` |

In the YAML of the full example above, the protection fields shown directly under a site (`mode`, `waf`, `acl`, `rate_limits`, `bot`, `api`, `login_protection`, `dlp`, `block_page`) are the site's `policy` block; M1 implements them under `policy:` from the start.

**Endpoint matching**: `path` (exact), `path_prefix`, or `path_glob`, plus optional `methods`. Precedence: exact > longest prefix/glob > any; method-specific > any method. Two endpoints with the same precedence that can match the same request fail validation. The compiler resolves effective policies at compile time and emits one Caddy subroute per endpoint (ordered by precedence), so there is no merging at request time.

**Effective view**: `GET /api/v1/sites/{site}/effective-policy?path=/wp-login.php&method=POST` returns the merged policy with `source` (`global`, `site`, `endpoint:<id>`) for each field.

## Milestone 1 subset

The file loader accepts `schema_version`, `global` (`trusted_proxies`, `client_ip_headers`, `acme`, `defaults`) and `sites` (`id`, `name`, `hosts`, `path_prefix`, `tls`, `upstreams`, `headers.security_headers`, `policy` with `mode`, `fail_mode`, `waf` and `block_page`, `endpoints`). **Any other key is a hard validation error** (`unknown_field`) so typos cannot silently disable protection; later milestones add their fields. `fail_mode` defaults to `closed` for `block` and `open` otherwise. `blocking_paranoia_level` defaults to the resolved `paranoia_level`. Endpoint `path_glob` uses Go `path.Match` syntax.

## Rules

- Secrets (CrowdSec key, upstream client keys, TOTP seeds) are never stored in the YAML. YAML references secret IDs; secrets live in the `secrets` table encrypted with the node key (see [data-model.md](data-model.md)). Export writes references, not values.
- `id` fields are stable slugs, unique within their parent, used in API paths and audit logs.
- Durations use Go duration strings. Sizes are bytes (integers).
- Every field has a default in `internal/config/defaults.go`; the API returns the effective (defaulted) config.
- Validation errors are returned as a list of `{path, code, message}` with JSON-pointer paths so the dashboard can attach errors to form fields.

## M8 tuning fields

All are part of the policy block, so they exist at global, site and endpoint level.

| Field | Meaning |
| --- | --- |
| `waf.exclusions[]` | `{id, description, match: {paths, methods}, remove_rule_ids, remove_tags, remove_targets: [{rule_ids, tags, target}]}`. Compiled to CRS-style runtime exclusion rules (ids from 9,100,000) placed before the CRS includes. Paths are globs (`*` stays inside a segment, trailing `/**` matches the prefix and below). Rule ids may be ranges (`942100-942199`). Rules 200000-200099 (body parsers), the virtual-patch range and custom rule ids cannot be excluded. Exclusions are part of one site's Coraza instance, so they never affect another site. |
| `waf.custom_rules` | Operator SecLang, ids 10000-99999, loaded after virtual patches and before the exclusions and CRS. Only `SecRule`, `SecAction` and `SecMarker`; actions are allow-listed (`exec`, `allow`, `redirect`, `initcol`, ... are refused); `ctl` only for `ruleRemove*` (never on Sherlock's own rules); `setvar` only on `tx.` and not on CRS control variables; operators that read files, run programs or use the network are refused. Validated by compiling in a throwaway Coraza instance. Scalar: the lowest level that sets it wins. |
| `waf.outbound_inspection` | Response inspection (CRS `RESPONSE-*` rules). `outbound_max_body_bytes` (default 1 MiB) bounds what is held and inspected; the rest streams through. `outbound_content_types` (prefix match, default `text/html`, `text/plain`, `application/json`, `application/xml`, `text/xml`) filters by media type. Compressed responses are not inspected; `Accept-Encoding` is removed from the upstream request while the feature is on. |
| `waf.blocking_paranoia_level` | May be lower than `paranoia_level`: rules above it still run and are recorded as findings (score and `paranoia-level/N` tag) but do not count towards blocking. The paranoia helper reads these findings back. |
| `stacks` | Declared technologies (`wordpress`, `php`, `spring`, ...). List semantics as for ACL lists (`[..]` replaces, `{add, remove}` edits). Unset or `[auto]`: generic patches only. |
| `virtual_patches` | `{enabled, disabled: [SV-YYYY-NNNN]}`. `disabled` is a named list (unioned across levels; drop an inherited entry with `opt_out: ["virtual_patches:<id>"]`). A product-specific patch is active only if the pack is enabled, the patch is not disabled and one of its `stacks` is declared. |
| `opt_out` | Besides `rate_limits:<name>`: `exclusions:<id>` and `virtual_patches:<id>`. |

Auto-detection of stacks (ADR-0013 `stacks: auto`) is not implemented: `auto` currently means "no stack declared".
