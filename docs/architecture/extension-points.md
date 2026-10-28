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
func main() { cli.Execute(extension.None()) }

// cmd/sherlock-ee/main.go (enterprise repo)
func main() {
    cli.Execute(extension.Bundle(
        enterprise.Modules()..., // defined in the private repository
    ))
}
```

`cli.Execute` lives in `pkg/cli` so both binaries share every command. Extensions can add CLI subcommands through `Host.RegisterCommand`.

## Interfaces

```go
package extension

type Extension interface {
    Name() string
    Init(ctx context.Context, h Host) error   // called once, after store and before data plane start
}

type Host interface {
    Logger() *slog.Logger
    DB() (*sql.DB, Dialect)                    // EE owns its own tables, prefixed ee_, with its own migrations
    Events() EventSubscriber                   // subscribe to the event bus
    RegisterAPIRoutes(prefix string, h http.Handler, perms map[string]Permission) // mounted under /api/v1/ee/
    RegisterCommand(cmd *cobra.Command)
    RegisterJob(name string, every time.Duration, fn func(context.Context) error)
    SetAuthorizer(Authorizer)
    AddAuthProvider(AuthProvider)
    AddAuditSink(AuditSink)
    SetEventStore(EventStore)
    AddExporterType(ExporterType)
    SetRateLimitBackend(RateLimitBackend)
    AddCompilerHook(CompilerHook)
    SetConfigSource(ConfigSource)
    AddReport(Report)
    AddFeatures(...Feature)                   // advertised in GET /system/info so the UI can show EE pages
}
```

| Interface | Core default | Enterprise implementation |
| --- | --- | --- |
| `Authorizer` | Two roles: admin, viewer | Custom roles, per-site permissions, teams |
| `AuthProvider` | Local username/password + TOTP | OIDC, SAML; SCIM via EE API routes |
| `AuditSink` | Writes to `audit_log` with hash chain | Signs chain checkpoints, ships to WORM/S3 Object Lock, verifies |
| `EventStore` | SQL event tables | ClickHouse |
| `ExporterType` | syslog/CEF, webhook, OTLP | Splunk HEC, Sentinel, Elastic, QRadar |
| `RateLimitBackend` | In-memory sharded sliding window | Valkey (cluster-wide) |
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
