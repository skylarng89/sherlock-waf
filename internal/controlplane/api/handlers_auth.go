package api

import (
	"context"
	"net/http"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// handlers implements apigen.StrictServerInterface.
type handlers struct{ s *Server }

var _ apigen.StrictServerInterface = (*handlers)(nil)

func (h *handlers) setSession(ctx context.Context, g auth.Grant) {
	w := writerFrom(ctx)
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: g.SessionToken, Path: "/", Expires: g.Expires,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	// Readable by the dashboard script, which echoes it in X-CSRF-Token. The
	// session cookie is HttpOnly; this one deliberately is not.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: not HttpOnly by design (double-submit token the dashboard must read)
		Name: CSRFCookie, Value: g.CSRFToken, Path: "/", Expires: g.Expires,
		Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearSession(ctx context.Context) {
	w := writerFrom(ctx)
	if w == nil {
		return
	}
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly mirrors how each cookie was set
			Name: name, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1,
			HttpOnly: name == SessionCookie, Secure: true, SameSite: http.SameSiteStrictMode,
		})
	}
}

func me(u store.User, perms []string) apigen.Me {
	if perms == nil {
		perms = []string{}
	}
	return apigen.Me{Id: u.ID, Username: u.Username, Role: apigen.MeRole(u.Role), Permissions: perms, MfaEnabled: u.MFAEnabled}
}

func (h *handlers) Login(ctx context.Context, req apigen.LoginRequestObject) (apigen.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	ua, _ := ctx.Value(keyUserAgent).(string)
	g, err := h.s.Auth.Login(ctx, ipFrom(ctx), ua, req.Body.Username, req.Body.Password)
	if err != nil {
		return nil, err
	}
	h.setSession(ctx, g)
	status := apigen.LoginResponseStatusMfaRequired
	if g.Stage == store.StageMFAEnrolRequire {
		status = apigen.LoginResponseStatusMfaEnrolRequired
	}
	return apigen.Login200JSONResponse{Status: status}, nil
}

func (h *handlers) VerifyMFA(ctx context.Context, req apigen.VerifyMFARequestObject) (apigen.VerifyMFAResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	ua, _ := ctx.Value(keyUserAgent).(string)
	g, err := h.s.Auth.VerifyMFA(ctx, principalFrom(ctx), ipFrom(ctx), ua, req.Body.Code)
	if err != nil {
		return nil, err
	}
	h.setSession(ctx, g)
	return apigen.VerifyMFA200JSONResponse(me(g.User, auth.RolePermissions(g.User.Role))), nil
}

func (h *handlers) StartMFAEnrolment(ctx context.Context, _ apigen.StartMFAEnrolmentRequestObject) (apigen.StartMFAEnrolmentResponseObject, error) {
	en, err := h.s.Auth.StartMFAEnrolment(ctx, principalFrom(ctx))
	if err != nil {
		return nil, err
	}
	return apigen.StartMFAEnrolment200JSONResponse{Secret: en.Secret, OtpauthUri: en.URI}, nil
}

func (h *handlers) ConfirmMFAEnrolment(ctx context.Context, req apigen.ConfirmMFAEnrolmentRequestObject) (apigen.ConfirmMFAEnrolmentResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	ua, _ := ctx.Value(keyUserAgent).(string)
	g, err := h.s.Auth.ConfirmMFAEnrolment(ctx, principalFrom(ctx), ipFrom(ctx), ua, req.Body.Code)
	if err != nil {
		return nil, err
	}
	h.setSession(ctx, g)
	return apigen.ConfirmMFAEnrolment200JSONResponse(me(g.User, auth.RolePermissions(g.User.Role))), nil
}

func (h *handlers) Logout(ctx context.Context, _ apigen.LogoutRequestObject) (apigen.LogoutResponseObject, error) {
	if err := h.s.Auth.Logout(ctx, principalFrom(ctx), ipFrom(ctx)); err != nil {
		return nil, err
	}
	clearSession(ctx)
	return apigen.Logout204Response{}, nil
}

func (h *handlers) GetMe(ctx context.Context, _ apigen.GetMeRequestObject) (apigen.GetMeResponseObject, error) {
	p := principalFrom(ctx)
	var u store.User
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		u, err = tx.UserByID(ctx, p.UserID)
		return err
	}); err != nil {
		return nil, err
	}
	return apigen.GetMe200JSONResponse(me(u, p.Permissions)), nil
}
