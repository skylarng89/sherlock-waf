# Extension points (for Enterprise)

Enterprise features are added by a separate binary, `sherlock-ee`, built in the private repository. It imports this repository as a Go module and registers implementations of the interfaces in `pkg/extension`. The open-source binary registers nothing and uses the default implementations.

**Rules**

1. Everything Enterprise needs MUST go through `pkg/extension`. Enterprise never imports `internal/...` (Go prevents it anyway).
2. Every interface has a working default in core. Core behaviour without extensions is complete, not crippled.
3. Interfaces are added to core in the same milestone that first needs them, with a core test using a fake implementation.
4. `pkg/extension` follows SemVer strictly from v1.0: breaking an interface is a major version bump of the module. Before v1.0, breaking changes are allowed but must be listed in the changelog under "Extension API".
5. No licence checks in core. Core does not know whether a licence exists.

## Bootstrapping

```go
// cmd/sherlock/main.go (core)
cli.Execute(ctx, info, cli.WithExtensions(extension.None()))

// cmd/sherlock-ee/main.go (enterprise repo)
cli.Execute(ctx, info, cli.WithExtensions(extension.Bundle(enterprise.Modules()...)))
```

`cli.Execute` lives in `pkg/cli` so both binaries share every command. `WithExtensions` is an `Option` (rather than a changed `Execute` signature) so existing callers keep compiling.

## Interfaces (v0, implemented in `pkg/extension`)

Only what the milestone that introduces a point needs is defined; the rest of the table below is added by the milestone that first uses it (rule 3).

```go
type Extension interface {
    Name() string
    Init(ctx context.Context, h Host) error   // once, after the store is open and before the data plane starts
}

type Host interface {              // implemented by the core; adding methods is not breaking
    CoreVersion() string
    Logger() *slog.Logger
    DB() (*sql.DB, Dialect)        // EE owns its own tables, prefixed ee_, with its own migrations
    Sessions() SessionIssuer       // AuthProviders turn an identity into a core session; the core keeps cookies, CSRF and MFA policy

    SetAuthorizer(Authorizer)
    AddAuthProvider(AuthProvider)
    AddAuditSink(AuditSink)
    SetEventStore(EventStore)
}
```

Design rules that keep the surface stable: implemented interfaces have one to three methods and exchange **structs** (`AuthzRequest`, `AuditRecord`, `EventQuery`, ...) so fields can be added; new optional behaviour arrives as a separate interface found by type assertion; every type in a signature lives in `pkg/extension` so Enterprise never imports `internal/`; failures use the sentinel errors `ErrNotFound` and `ErrDenied`. `extension/extensiontest` provides a fake `Host`.

Added by later milestones (see the table): `RegisterAPIRoutes`, `RegisterJob`, `Events()` subscription, `AddExporterType` (M10), `SetRateLimitBackend` (M5), `AddCompilerHook`, `SetConfigSource`, `AddReport`, `AddFeatures`. `RegisterCommand` is deliberately not planned: it would put cobra into the public API.

| Interface | Core default | Enterprise implementation |
| --- | --- | --- |
| `Authorizer` | Two roles: admin, viewer. Must fail closed: an error counts as a denial | Custom roles, per-site permissions, teams |
| `AuthProvider` | Local username/password + TOTP | OIDC, SAML; SCIM via EE API routes |
| `AuditSink` | The core writes the hash-chained `audit_log` inside the audited transaction; sinks are **post-commit observers** that receive the chained record | Signs chain checkpoints, ships to WORM/S3 Object Lock, verifies |
| `EventStore` | SQL event tables | ClickHouse |
| `ExporterType` (M10) | syslog/CEF, webhook, OTLP | Splunk HEC, Sentinel, Elastic, QRadar |
| `RateLimitBackend` (M5) | In-memory sharded sliding window | Valkey (cluster-wide) |
| `CompilerHook` | none | Adds cluster headers, EE Caddy modules into routes |
| `ConfigSource` | Local store | Cluster control plane pushes signed config to nodes |
| `Report` | none | PCI DSS evidence pack, scheduled PDF reports |

Enterprise Caddy modules (if any) register themselves with `caddy.RegisterModule` in their package `init()`; importing the package in `cmd/sherlock-ee` is enough. The compiler places them via a `CompilerHook`.

## Dashboard extension

The dashboard in `web/` exposes a small registration API in `web/src/extensions.ts`:

```ts
export interface DashboardExtension {
  id: string
  feature: string                 // shown only if GET /system/info lists this feature
  routes: RouteRecordRaw[]
  navItems: NavItem[]
  siteTabs?: SiteTab[]            // extra tabs on the site detail page
  settingsPages?: SettingsPage[]
}
export function registerExtension(ext: DashboardExtension): void
```

Core calls nothing. The Enterprise repository builds the dashboard from the core source (pinned via git submodule at the same tag as the Go module) with an extra entry file that imports EE pages and calls `registerExtension` before mounting the app. The result is embedded into `sherlock-ee`. Shared components, stores and the API client are imported from core, so EE pages look native.

## Compatibility guarantee

Each `sherlock-ee` release states the exact core version it embeds (same `MAJOR.MINOR.PATCH`). There is no mixing of versions at runtime: a node runs either `sherlock` or `sherlock-ee`, and switching between them on the same data directory is supported in both directions (EE tables are ignored by core).
