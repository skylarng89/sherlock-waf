package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// host is the extension.Host the core offers extensions.
type host struct {
	version string
	log     *slog.Logger
	st      store.Store

	authorizer extension.Authorizer
	providers  []extension.AuthProvider
	auditSinks []extension.AuditSink
	eventStore extension.EventStore
}

func newHost(o Options, env *ops.Env, log *slog.Logger) *host {
	return &host{version: o.Info.Version, log: log, st: env.Store}
}

func (h *host) CoreVersion() string  { return h.version }
func (h *host) Logger() *slog.Logger { return h.log }

func (h *host) DB() (*sql.DB, extension.Dialect) {
	p, ok := h.st.(store.SQLProvider)
	if !ok {
		return nil, ""
	}
	return p.SQLDB(), extension.Dialect(h.st.Dialect())
}

func (h *host) Sessions() extension.SessionIssuer { return unsupportedIssuer{} }

func (h *host) SetAuthorizer(a extension.Authorizer) { h.authorizer = a }

func (h *host) AddAuthProvider(p extension.AuthProvider) { h.providers = append(h.providers, p) }

func (h *host) AddAuditSink(s extension.AuditSink) { h.auditSinks = append(h.auditSinks, s) }

func (h *host) SetEventStore(s extension.EventStore) {
	h.eventStore = s
	h.log.Warn("an extension registered an event store; the core API still reads the SQL tables until M7 routes it through")
}

// unsupportedIssuer: issuing a session on behalf of an external identity needs
// the SSO policy (role mapping, MFA exemption) that belongs to the extension
// contract's next revision. Until then it refuses rather than guess.
type unsupportedIssuer struct{}

var errIssuerUnsupported = errors.New("extension session issuing is not available in this core version")

func (unsupportedIssuer) Issue(context.Context, http.ResponseWriter, *http.Request, extension.Principal) error {
	return errIssuerUnsupported
}

// mountProviders serves each AuthProvider under /api/v1/auth/providers/<name>/.
// The providers' routes run outside the guard on purpose: sign-in is where
// authentication starts, and they must call Sessions().Issue to get a session.
func mountProviders(mux *http.ServeMux, ps []extension.AuthProvider) {
	for _, p := range ps {
		prefix := "/api/v1/auth/providers/" + p.Name() + "/"
		mux.Handle(prefix, http.StripPrefix(prefix[:len(prefix)-1], p.Routes()))
	}
}
