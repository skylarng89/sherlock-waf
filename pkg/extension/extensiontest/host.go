// Package extensiontest provides a fake extension.Host so the core and
// extensions can test registration without a running node.
package extensiontest

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"sync"

	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Host records what an extension registers.
type Host struct {
	mu sync.Mutex

	Version string
	Log     *slog.Logger
	Dialect extension.Dialect
	Conn    *sql.DB
	Issuer  extension.SessionIssuer

	Authorizer    extension.Authorizer
	AuthProviders []extension.AuthProvider
	AuditSinks    []extension.AuditSink
	EventStore    extension.EventStore
}

var _ extension.Host = (*Host)(nil)

// New returns a Host with usable defaults.
func New() *Host {
	return &Host{Version: "test", Log: slog.New(slog.DiscardHandler), Dialect: extension.DialectSQLite, Issuer: noSessions{}}
}

// CoreVersion implements extension.Host.
func (h *Host) CoreVersion() string { return h.Version }

// Logger implements extension.Host.
func (h *Host) Logger() *slog.Logger { return h.Log }

// DB implements extension.Host.
func (h *Host) DB() (*sql.DB, extension.Dialect) { return h.Conn, h.Dialect }

// Sessions implements extension.Host.
func (h *Host) Sessions() extension.SessionIssuer { return h.Issuer }

// SetAuthorizer implements extension.Host.
func (h *Host) SetAuthorizer(a extension.Authorizer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Authorizer = a
}

// AddAuthProvider implements extension.Host.
func (h *Host) AddAuthProvider(p extension.AuthProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthProviders = append(h.AuthProviders, p)
}

// AddAuditSink implements extension.Host.
func (h *Host) AddAuditSink(s extension.AuditSink) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuditSinks = append(h.AuditSinks, s)
}

// SetEventStore implements extension.Host.
func (h *Host) SetEventStore(s extension.EventStore) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.EventStore = s
}

type noSessions struct{}

func (noSessions) Issue(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ extension.Principal) error {
	return nil
}
