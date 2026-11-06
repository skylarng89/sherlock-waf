package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const freshPassword = "another long passphrase"

type sessionItem struct {
	ID      string `json:"id"`
	Current bool   `json:"current"`
}

func listSessions(t *testing.T, s *session) []sessionItem {
	t.Helper()
	r := s.do("GET", "/auth/sessions", nil)
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	var body struct {
		Items []sessionItem `json:"items"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &body))
	return body.Items
}

func fieldErrorPath(t *testing.T, r resp) string {
	t.Helper()
	body := r.JSON(t)
	errs, ok := body["errors"].([]any)
	require.True(t, ok, "422 carries errors[]: %s", r.Body)
	require.NotEmpty(t, errs)
	return errs[0].(map[string]any)["path"].(string)
}

func TestSelfServicePasswordChangeEndsOtherSessionsAndAudits(t *testing.T) {
	h := newHarness(t)
	caller := h.mint(h.view, store.StageFull)
	other := h.mint(h.view, store.StageFull)
	require.Equal(t, http.StatusOK, other.do("GET", "/auth/me", nil).Status)

	r := caller.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword})
	require.Equal(t, http.StatusNoContent, r.Status, string(r.Body))

	assert.Equal(t, http.StatusUnauthorized, other.do("GET", "/auth/me", nil).Status, "other sessions end")
	assert.Equal(t, http.StatusOK, caller.do("GET", "/auth/me", nil).Status, "the caller stays signed in")

	_, err := h.auth.Login(t.Context(), "", "ua", "vic", pw)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "the old password stops working")
	_, err = h.auth.Login(t.Context(), "", "ua", "vic", freshPassword)
	require.NoError(t, err, "the new password works")

	audit := adminSession(h).do("GET", "/audit", nil)
	assert.Contains(t, string(audit.Body), "user.password_changed")
	assert.Contains(t, string(audit.Body), "sessions_revoked")
	assert.NotContains(t, string(audit.Body), freshPassword)
	assert.NotContains(t, string(audit.Body), pw)
}

func TestWrongCurrentPasswordIsUnprocessableThrottlesAndAudits(t *testing.T) {
	h := newHarness(t)
	caller := h.mint(h.view, store.StageFull)

	for range 5 {
		r := caller.do("POST", "/auth/password", map[string]any{"current_password": "not the password", "new_password": freshPassword})
		require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
		assert.Equal(t, "/current_password", fieldErrorPath(t, r))
	}
	r := caller.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword})
	assert.Equal(t, http.StatusTooManyRequests, r.Status, "the attempt bound applies even to the right password")
	assert.NotEmpty(t, r.Header.Get("Retry-After"))

	assert.Equal(t, http.StatusOK, caller.do("GET", "/auth/me", nil).Status, "a failed change does not sign the user out or lock the account")
	audit := string(adminSession(h).do("GET", "/audit", nil).Body)
	assert.Contains(t, audit, "user.password_change_failed")
	assert.Contains(t, audit, "bad_current_password")
	assert.NotContains(t, audit, "not the password")
}

func TestNewPasswordMustBeStrongAndDifferent(t *testing.T) {
	cases := []struct {
		name string
		next string
	}{
		{"unchanged", pw},
		{"too short for the schema", "short"},
		{"common and predictable", "password1234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			caller := h.mint(h.view, store.StageFull)
			r := caller.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": tc.next})
			require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
			assert.Equal(t, "/new_password", fieldErrorPath(t, r))
			_, err := h.auth.Login(t.Context(), "", "ua", "vic", pw)
			require.NoError(t, err, "a refused change leaves the password alone")
		})
	}
}

func TestSessionListAndRevoke(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	other := h.mint(h.admin, store.StageFull)
	require.Equal(t, http.StatusOK, other.do("GET", "/auth/me", nil).Status)

	items := listSessions(t, a)
	require.Len(t, items, 2)
	var current, sibling string
	for _, it := range items {
		if it.Current {
			current = it.ID
		} else {
			sibling = it.ID
		}
	}
	require.NotEmpty(t, current)
	require.NotEmpty(t, sibling)

	assert.Equal(t, http.StatusConflict, a.do("DELETE", "/auth/sessions/"+current, nil).Status, "sign out ends the current session")
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/auth/sessions/no-such-session", nil).Status)

	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/auth/sessions/"+sibling, nil).Status)
	assert.Equal(t, http.StatusUnauthorized, other.do("GET", "/auth/me", nil).Status, "the revoked session is dead")
	assert.Len(t, listSessions(t, a), 1)
}

func TestSessionRevokeIsIDORSafe(t *testing.T) {
	h := newHarness(t)
	victim := h.mint(h.view, store.StageFull)
	attacker := adminSession(h)
	victimItems := listSessions(t, victim)
	require.Len(t, victimItems, 1)
	victimSession := victimItems[0].ID

	for _, it := range listSessions(t, attacker) {
		assert.NotEqual(t, victimSession, it.ID, "a user's list never shows another user's sessions")
	}
	assert.Equal(t, http.StatusNotFound, attacker.do("DELETE", "/auth/sessions/"+victimSession, nil).Status,
		"another user's session id is reported as not found")
	assert.Equal(t, http.StatusOK, victim.do("GET", "/auth/me", nil).Status, "the victim's session survives")
}

func TestAccountRoutesRefuseTokensPartialSessionsAndAnonymous(t *testing.T) {
	h := newHarness(t)
	partial := h.mint(h.admin, store.StagePasswordOK)
	token := h.token(h.admin, []string{auth.ScopeAdmin}, nil)
	body := map[string]any{"current_password": pw, "new_password": freshPassword}

	for name, s := range map[string]*session{"token": token, "partial": partial} {
		r := s.do("POST", "/auth/password", body)
		assert.Equal(t, http.StatusForbidden, r.Status, name)
		assert.Equal(t, problemBase+"forbidden", r.JSON(t)["type"], name)
		assert.Equal(t, http.StatusForbidden, s.do("GET", "/auth/sessions", nil).Status, name)
		assert.Equal(t, http.StatusForbidden, s.do("DELETE", "/auth/sessions/x", nil).Status, name)
	}
	anon := h.anon()
	assert.Equal(t, http.StatusUnauthorized, anon.do("POST", "/auth/password", body).Status)
	assert.Equal(t, http.StatusUnauthorized, anon.do("GET", "/auth/sessions", nil).Status)
}

// enrolledAdmin signs ada in, enrols two-step verification and returns the full
// session and the authenticator seed.
func enrolledAdmin(t *testing.T, h *harness) (*session, string) {
	t.Helper()
	c := h.anon()
	require.Equal(t, http.StatusOK, c.do("POST", "/auth/login", map[string]string{"username": "ada", "password": pw}).Status)
	c.csrf = cookieValue(t, c, CSRFCookie)
	en := c.do("POST", "/auth/mfa/enroll", nil)
	require.Equal(t, http.StatusOK, en.Status, string(en.Body))
	seed := en.JSON(t)["secret"].(string)
	done := c.do("POST", "/auth/mfa/enroll/confirm", map[string]string{"code": totpNow(t, seed)})
	require.Equal(t, http.StatusOK, done.Status, string(done.Body))
	c.csrf = cookieValue(t, c, CSRFCookie)
	return c, seed
}

// wrongCode returns a six-digit code that is not valid at any step the server
// accepts, so a test cannot pass or fail by chance.
func wrongCode(t *testing.T, seed string) string {
	t.Helper()
	valid := map[string]bool{}
	for off := int64(-1); off <= 1; off++ {
		valid[totpAt(t, seed, off)] = true
	}
	for n := 135790; ; n++ {
		if c := fmt.Sprintf("%06d", n); !valid[c] {
			return c
		}
	}
}

func TestPasswordChangeNeedsACurrentCodeWhenMFAIsEnrolled(t *testing.T) {
	h := newHarness(t)
	c, seed := enrolledAdmin(t, h)

	r := c.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword})
	require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	assert.Equal(t, "/totp_code", fieldErrorPath(t, r), "a session alone cannot change the password")

	bad := wrongCode(t, seed)
	r = c.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword, "totp_code": bad})
	require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	assert.Equal(t, "/totp_code", fieldErrorPath(t, r))

	r = c.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword, "totp_code": "12345"})
	assert.Equal(t, http.StatusUnprocessableEntity, r.Status, "a malformed code is refused by the schema")

	// The enrolment code is spent; the next step's code is valid and unused.
	r = c.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword, "totp_code": totpAt(t, seed, 1)})
	require.Equal(t, http.StatusNoContent, r.Status, string(r.Body))
	assert.Equal(t, http.StatusOK, c.do("GET", "/auth/me", nil).Status, "the caller stays signed in")

	audit := string(adminSession(h).do("GET", "/audit", nil).Body)
	assert.Contains(t, audit, "mfa_required")
	assert.Contains(t, audit, "bad_mfa_code")
	assert.NotContains(t, audit, bad, "codes never reach the audit log")
}
