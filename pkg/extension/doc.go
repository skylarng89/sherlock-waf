// Package extension is the contract between the open-source core and
// Enterprise (or any third-party) builds. An extension is a Go package that is
// compiled into a separate binary; it registers implementations of the
// interfaces below with the Host while the node starts.
//
// # Compatibility
//
// This package is frozen at v1.0.0 and follows SemVer strictly: within v1 only
// additions are made, and a breaking change needs a new major version with a
// /v2 module path (docs/release/versioning.md). Releases list additions under
// "Extension API" in the changelog, and a test (TestAPIGuard) compares the
// exported surface with testdata/api.txt, so any change to it is a visible,
// deliberate golden-file update in review. To keep the promise cheap, the
// package is built so it can grow without breaking implementers:
//
//   - Interfaces that extensions implement (Authorizer, AuthProvider, AuditSink,
//     EventStore) stay small, and take and return structs: adding a field to a
//     request or record struct is not a breaking change.
//   - The core implements Host, so adding a method to Host is also not breaking
//     for extensions.
//   - New optional behaviour is added as a separate interface that an extension
//     may also implement; the core discovers it with a type assertion.
//   - Every type used in a signature lives in this package. Extensions never
//     import the core's internal packages.
//
// A node runs either the core or an extension build compiled against exactly one
// core version, so there is no runtime version negotiation (see CoreVersion).
package extension
