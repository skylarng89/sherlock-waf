package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func (h *handlers) userCount(ctx context.Context) (n int, err error) {
	err = h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		n, err = tx.CountUsers(ctx)
		return err
	})
	return n, err
}

func (h *handlers) GetSetupStatus(ctx context.Context, _ apigen.GetSetupStatusRequestObject) (apigen.GetSetupStatusResponseObject, error) {
	n, err := h.userCount(ctx)
	if err != nil {
		return nil, err
	}
	return apigen.GetSetupStatus200JSONResponse{SetupRequired: n == 0 && h.s.Setup.Active()}, nil
}

func (h *handlers) CreateFirstAdmin(ctx context.Context, req apigen.CreateFirstAdminRequestObject) (apigen.CreateFirstAdminResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	closed := errConflict("setup is already complete")
	if !h.s.Setup.Active() {
		return nil, closed
	}
	if n, err := h.userCount(ctx); err != nil {
		return nil, err
	} else if n > 0 {
		return nil, closed
	}
	if !usernamePattern.MatchString(b.Username) {
		return nil, errBadRequest("username must be 3-64 characters from A-Z a-z 0-9 . _ -")
	}
	if err := auth.ValidatePassword(b.Password); err != nil {
		return nil, err
	}
	hash, err := h.s.Hasher.Hash(ctx, b.Password)
	if err != nil {
		return nil, err
	}

	ok, wait := h.s.Setup.attempt(b.SetupToken)
	switch {
	case wait > 0:
		return nil, &auth.ThrottledError{RetryAfter: wait}
	case !ok:
		h.auditAnonymous(ctx, "setup.denied", nil)
		return nil, errForbidden("The setup token is not valid.")
	}

	now := h.s.Now()
	id, err := ids.New(now)
	if err != nil {
		h.s.Setup.restore(b.SetupToken)
		return nil, err
	}
	u := store.User{ID: id, Username: b.Username, PasswordHash: hash, Role: auth.RoleAdmin, CreatedAt: now}
	var entry store.AuditEntry
	err = h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		// Re-check inside the transaction: a user created by the CLI since the first check wins.
		n, err := tx.CountUsers(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return closed
		}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		entry, err = h.s.Audit.Append(ctx, tx, audit.Input{
			ActorType: audit.ActorSystem, ActorID: "setup", IP: ipFrom(ctx), Action: "setup.admin_created",
			ObjectType: "user", ObjectID: id, Details: map[string]any{"username": b.Username},
		})
		return err
	})
	if err != nil {
		if !errors.Is(err, closed) {
			h.s.Setup.restore(b.SetupToken) // the admin was not created; do not burn the token
		}
		return nil, err
	}
	h.s.Audit.Deliver(ctx, entry)
	return apigen.CreateFirstAdmin201JSONResponse(userDTO(u, now)), nil
}

func (h *handlers) auditAnonymous(ctx context.Context, action string, details any) {
	if err := h.s.Audit.Record(ctx, h.s.Store, audit.Input{ActorType: audit.ActorSystem, ActorID: "anonymous", IP: ipFrom(ctx), Action: action, Details: details}); err != nil {
		h.s.log.Error("recording audit entry failed", "action", action, "error", err)
	}
}

// --- upstream test ---

const upstreamTestTimeout = 3 * time.Second

func (h *handlers) TestUpstream(ctx context.Context, req apigen.TestUpstreamRequestObject) (apigen.TestUpstreamResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(b.Target))
	if err != nil || host == "" {
		return nil, errBadRequest("target must be host:port.")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, errBadRequest("target must be host:port with a port from 1 to 65535.")
	}
	useTLS := b.Tls != nil && *b.Tls
	skip := b.TlsSkipVerify != nil && *b.TlsSkipVerify
	res := h.s.checkUpstream(ctx, host, port, useTLS, skip)
	h.auditAnonymousActor(ctx, "system.test_upstream", map[string]any{"target": b.Target, "reachable": res.Reachable})
	return apigen.TestUpstream200JSONResponse(res), nil
}

func (h *handlers) auditAnonymousActor(ctx context.Context, action string, details any) {
	p := principalFrom(ctx)
	in := audit.Input{ActorType: audit.ActorUser, ActorID: p.UserID, IP: ipFrom(ctx), Action: action, Details: details}
	if p.IsToken() {
		in.ActorType, in.ActorID = audit.ActorToken, p.TokenID
	}
	if err := h.s.Audit.Record(ctx, h.s.Store, in); err != nil {
		h.s.log.Error("recording audit entry failed", "action", action, "error", err)
	}
}

// checkUpstream connects and sends HEAD /, without following redirects and
// without returning any response content: only the status code and a short
// failure class leave this function, so the endpoint cannot be used to read
// internal services.
func (s *Server) checkUpstream(ctx context.Context, host, port string, useTLS, skipVerify bool) apigen.TestUpstreamResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, upstreamTestTimeout)
	defer cancel()
	fail := func(class string) apigen.TestUpstreamResult {
		return apigen.TestUpstreamResult{Reachable: false, LatencyMs: int(time.Since(start).Milliseconds()), Error: &class}
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	// Upstreams are often on private networks, so loopback and RFC 1918 stay allowed; link-local
	// (cloud metadata), multicast and unspecified addresses are refused at dial time.
	client := netx.NewClient(netx.Options{AllowPrivate: true, Timeout: upstreamTestTimeout})
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.DisableKeepAlives = true
		if useTLS {
			tr.TLSClientConfig = tlsClient(skipVerify)
		}
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodHead, fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, port)), nil)
	if err != nil {
		return fail("protocol")
	}
	resp, err := client.Do(r)
	if err != nil {
		return fail(classifyDialError(err))
	}
	_ = resp.Body.Close()
	status := resp.StatusCode
	return apigen.TestUpstreamResult{Reachable: true, Status: &status, LatencyMs: int(time.Since(start).Milliseconds())}
}
