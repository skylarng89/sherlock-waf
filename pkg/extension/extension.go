package extension

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Sentinel errors. Implementations return them (possibly wrapped) so the core
// can map them to the right API response.
var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("extension: not found")
	// ErrDenied means the caller is not allowed to do what it asked.
	ErrDenied = errors.New("extension: denied")
)

// Extension is one unit of added behaviour.
type Extension interface {
	// Name identifies the extension in logs and in GET /system/info.
	Name() string
	// Init is called once, after the store is open and before the data plane
	// starts. It registers its implementations with h.
	Init(ctx context.Context, h Host) error
}

// Dialect names the database engine behind Host.DB.
type Dialect string

// Database engines.
const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// Host is what the core offers an extension. Methods may be added over time.
type Host interface {
	// CoreVersion is the version of the core this node was built from.
	CoreVersion() string
	Logger() *slog.Logger
	// DB returns the node's database for the extension's own tables, which must
	// be prefixed "ee_" and migrated by the extension.
	DB() (*sql.DB, Dialect)
	// Sessions lets an AuthProvider turn an authenticated identity into a core session.
	Sessions() SessionIssuer

	SetAuthorizer(Authorizer)
	AddAuthProvider(AuthProvider)
	AddAuditSink(AuditSink)
	SetEventStore(EventStore)
}

// Permission names an operation, such as "config:write". The core defines the
// set; an extension's Authorizer decides who holds each.
type Permission string

// Principal is who is acting.
type Principal struct {
	// Type is "user", "token" or "system".
	Type     string
	ID       string
	Username string
	// Role is the core role ("admin", "viewer") for local accounts; extensions
	// may map external identities onto it.
	Role string
	// Scopes are the scopes of an API token, empty otherwise.
	Scopes []string
	// Attributes carries extension-defined claims (groups, tenant).
	Attributes map[string]string
}

// AuthzRequest is one authorisation question.
type AuthzRequest struct {
	Principal  Principal
	Permission Permission
	// Resource narrows the question, such as "sites/shop"; empty means global.
	Resource string
}

// Decision is the answer to an AuthzRequest.
type Decision struct {
	Allow bool
	// Reason is recorded in the audit log when the request is denied.
	Reason string
}

// Authorizer decides whether a principal may perform a permission. The core's
// default knows two roles; implementations must fail closed (a non-nil error is
// treated as a denial).
type Authorizer interface {
	Authorize(ctx context.Context, req AuthzRequest) (Decision, error)
}

// AuthProvider adds a sign-in method such as OIDC or SAML. The core mounts
// Routes() under /api/v1/auth/providers/<Name>/. After authenticating a user the
// provider calls Host.Sessions().Issue; the core keeps ownership of sessions,
// cookie flags, CSRF and the MFA policy.
type AuthProvider interface {
	Name() string
	Routes() http.Handler
}

// SessionIssuer creates core sessions on behalf of an AuthProvider.
type SessionIssuer interface {
	// Issue sets the session cookies on w for p. A user with no local MFA
	// enrolment is routed through the core's enrolment flow where policy requires it.
	Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, p Principal) error
}

// AuditRecord is one committed audit entry, already chained.
type AuditRecord struct {
	Seq        int64
	ID         string
	At         time.Time
	ActorType  string
	ActorID    string
	IP         string
	Action     string
	ObjectType string
	ObjectID   string
	Details    json.RawMessage
	PrevHash   string
	Hash       string
}

// AuditSink receives audit records after they are committed, for example to sign
// chain checkpoints or ship them to write-once storage. It is an observer: the
// hash chain itself is written by the core inside the audited transaction.
// Delivery errors are logged and never fail the audited operation.
type AuditSink interface {
	Deliver(ctx context.Context, rec AuditRecord) error
}

// EventRecord is a security event as stored.
type EventRecord struct {
	ID       string
	TS       time.Time
	SiteID   string
	Action   string
	ClientIP string
	RuleIDs  []string
	// Body is the full event document (docs/reference/event.schema.json).
	Body json.RawMessage
}

// EventQuery selects events; zero fields are ignored.
type EventQuery struct {
	SiteID   string
	Action   string
	ClientIP string
	RuleID   string
	From, To time.Time
	// Cursor is the opaque NextCursor of a previous page.
	Cursor string
	Limit  int
}

// EventPage is one page of query results, newest first.
type EventPage struct {
	Items      []EventRecord
	NextCursor string
}

// EventStore replaces the SQL event tables, for example with ClickHouse. Get
// returns ErrNotFound for an unknown id.
type EventStore interface {
	Write(ctx context.Context, events []EventRecord) error
	Get(ctx context.Context, id string) (EventRecord, error)
	Query(ctx context.Context, q EventQuery) (EventPage, error)
}

type none struct{}

func (none) Name() string                     { return "none" }
func (none) Init(context.Context, Host) error { return nil }

// None is the extension set of the open-source binary: it registers nothing.
func None() Extension { return none{} }

type bundle []Extension

func (b bundle) Name() string {
	name := ""
	for i, e := range b {
		if i > 0 {
			name += "+"
		}
		name += e.Name()
	}
	return name
}

func (b bundle) Init(ctx context.Context, h Host) error {
	for _, e := range b {
		if err := e.Init(ctx, h); err != nil {
			return fmt.Errorf("initialising extension %q: %w", e.Name(), err)
		}
	}
	return nil
}

// Bundle combines extensions; they are initialised in order and the first error stops startup.
func Bundle(exts ...Extension) Extension {
	if len(exts) == 0 {
		return None()
	}
	return bundle(exts)
}
