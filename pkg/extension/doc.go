// Package extension is the contract between the open-source core and
// Enterprise (or any third-party) builds. An extension is a Go package that is
// compiled into a separate binary; it registers implementations of the
// interfaces below with the Host while the node starts.
//
// # Compatibility
//
// Before v1.0 breaking changes are allowed but are listed in the changelog under
// "Extension API". From v1.0 this package follows SemVer strictly. To keep that
// promise cheap, the package is built so it can grow without breaking
// implementers:
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
