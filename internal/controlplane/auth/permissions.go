package auth

import "slices"

// Roles.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Permissions, as named by x-sherlock-permission in api/openapi.yaml.
const (
	PermPublic        = "public"        // no authentication
	PermAuthenticated = "authenticated" // any full session or token
	PermSessionAny    = "session-any"   // any session, including a partial one
	PermSessionPart   = "session-partial"
	PermConfigRead    = "config:read"
	PermConfigWrite   = "config:write"
	PermEventsRead    = "events:read"
	PermUsersManage   = "users:manage"
	PermTokensOwn     = "tokens:own"
	PermAuditRead     = "audit:read"
	PermSystemRead    = "system:read"
	// PermSystemUpdate installs a new binary: admin only, and never part of the read or write scopes.
	PermSystemUpdate = "system:update"
)

var rolePerms = map[string][]string{
	RoleAdmin:  {PermConfigRead, PermConfigWrite, PermEventsRead, PermUsersManage, PermTokensOwn, PermAuditRead, PermSystemRead, PermSystemUpdate},
	RoleViewer: {PermConfigRead, PermEventsRead, PermTokensOwn, PermSystemRead},
}

// Token scopes.
const (
	ScopeRead   = "read"
	ScopeWrite  = "write"
	ScopeEvents = "events:read"
	ScopeAdmin  = "admin"
)

// ValidScope reports whether s is a defined token scope.
func ValidScope(s string) bool {
	return slices.Contains([]string{ScopeRead, ScopeWrite, ScopeEvents, ScopeAdmin}, s)
}

var scopePerms = map[string][]string{
	ScopeRead:   {PermConfigRead, PermSystemRead},
	ScopeWrite:  {PermConfigRead, PermConfigWrite, PermSystemRead},
	ScopeEvents: {PermEventsRead},
	// admin grants everything the owner's role has except minting more tokens.
	ScopeAdmin: {PermConfigRead, PermConfigWrite, PermEventsRead, PermUsersManage, PermAuditRead, PermSystemRead, PermSystemUpdate},
}

// RolePermissions lists what a role may do; an unknown role gets nothing.
func RolePermissions(role string) []string { return slices.Clone(rolePerms[role]) }

// TokenPermissions is the intersection of the scopes' permissions and the
// owner's role, so demoting a user also narrows their tokens. tokens:own is
// never granted to a token: tokens are minted from a session only.
func TokenPermissions(role string, scopes []string) []string {
	allowed := rolePerms[role]
	var out []string
	for _, s := range scopes {
		for _, p := range scopePerms[s] {
			if slices.Contains(allowed, p) && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Has reports whether perms satisfies need.
func Has(perms []string, need string) bool { return slices.Contains(perms, need) }
