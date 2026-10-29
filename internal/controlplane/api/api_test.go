package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const wrongAttempt = "nope nope nope"

var paramRe = regexp.MustCompile(`\{[^}]+\}`)

type op struct{ method, path, perm string }

func specOps(t *testing.T) []op {
	t.Helper()
	spec, err := apigen.GetSpec()
	require.NoError(t, err)
	table, err := permissionTable()
	require.NoError(t, err)
	var ops []op
	for p, item := range spec.Paths.Map() {
		for m := range item.Operations() {
			ops = append(ops, op{m, p, table[m+" "+BasePath+p]})
		}
	}
	slices.SortFunc(ops, func(a, b op) int { return strings.Compare(a.method+a.path, b.method+b.path) })
	require.GreaterOrEqual(t, len(ops), 37)
	return ops
}

// Independent of the production tables on purpose: if someone widens a role or
// scope there, this matrix fails.
var (
	viewerPerms = []string{"config:read", "events:read", "tokens:own", "system:read"}
	adminPerms  = []string{"config:read", "config:write", "events:read", "users:manage", "tokens:own", "audit:read", "system:read"}
	tokenPerms  = map[string][]string{
		"read":        {"config:read", "system:read"},
		"write":       {"config:read", "config:write", "system:read"},
		"events:read": {"events:read"},
		"admin":       {"config:read", "config:write", "events:read", "users:manage", "audit:read", "system:read"},
	}
)

func allowed(perm string, kind string, held []string) bool {
	switch perm {
	case "public":
		return true
	case "session-any":
		return kind == "full" || kind == "partial"
	case "session-partial":
		return kind == "partial"
	case "authenticated":
		return kind == "full" || kind == "token"
	}
	return (kind == "full" || kind == "token") && slices.Contains(held, perm)
}

func TestEveryOperationDeclaresAKnownPermission(t *testing.T) {
	for _, o := range specOps(t) {
		assert.NotEmpty(t, o.perm, "%s %s", o.method, o.path)
	}
}

func TestAuthorisationMatrix(t *testing.T) {
	h := newHarness(t)
	ops := specOps(t)

	type who struct {
		name string
		kind string
		held []string
		make func() *session
	}
	people := []who{
		{"anonymous", "none", nil, h.anon},
		{"viewer", "full", viewerPerms, func() *session { return h.mint(h.view, store.StageFull) }},
		{"admin", "full", adminPerms, func() *session { return h.mint(h.admin, store.StageFull) }},
		{"partial", "partial", nil, func() *session { return h.mint(h.admin, store.StagePasswordOK) }},
	}
	for scope, perms := range tokenPerms {
		people = append(people, who{"token:" + scope, "token", perms, func() *session { return h.token(h.admin, []string{scope}, nil) }})
	}

	for _, o := range ops {
		for _, p := range people {
			t.Run(p.name+"/"+o.method+" "+o.path, func(t *testing.T) {
				s := p.make()
				path := paramRe.ReplaceAllString(o.path, "x")
				var body any
				if o.method != http.MethodGet && o.method != http.MethodDelete {
					body = "{}"
				}
				r := s.do(o.method, path, body)
				// Only the guard's own refusals count: a handler may legitimately
				// answer 401 (bad password) or 403 (wrong sign-in step) after
				// authorisation has passed.
				typ, _ := jsonField(r, "type")
				denied := typ == problemBase+"unauthenticated" || typ == problemBase+"forbidden"
				want := allowed(o.perm, p.kind, p.held)
				if want {
					assert.False(t, denied, "expected to pass authorisation, got %d %s", r.Status, r.Body)
				} else {
					assert.True(t, denied, "expected 401/403, got %d %s", r.Status, r.Body)
					if p.kind == "none" {
						assert.Equal(t, http.StatusUnauthorized, r.Status)
					}
				}
				assert.Equal(t, "no-store", r.Header.Get("Cache-Control"))
			})
		}
	}
}

func jsonField(r resp, key string) (string, bool) {
	var m map[string]any
	if json.Unmarshal(r.Body, &m) != nil {
		return "", false
	}
	v, ok := m[key].(string)
	return v, ok
}

func TestUnknownRoutesAreProblemDocuments(t *testing.T) {
	h := newHarness(t)
	r := h.anon().do("GET", "/nope", nil)
	assert.Equal(t, http.StatusNotFound, r.Status)
	assert.Equal(t, "application/problem+json", r.Header.Get("Content-Type"))
	assert.Equal(t, "urn:sherlock:problem:not_found", r.JSON(t)["type"])
	assert.NotEmpty(t, r.Header.Get("X-Request-Id"))
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)
	for _, r := range []resp{h.anon().do("GET", "/auth/me", nil), h.anon().do("GET", "/nope", nil), h.mint(h.admin, store.StageFull).do("GET", "/config", nil)} {
		assert.Equal(t, "nosniff", r.Header.Get("X-Content-Type-Options"))
		assert.Contains(t, r.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'")
		assert.Contains(t, r.Header.Get("Strict-Transport-Security"), "max-age=")
		assert.Equal(t, "no-referrer", r.Header.Get("Referrer-Policy"))
	}
}

func TestCSRFIsRequiredForSessionsButNotTokens(t *testing.T) {
	h := newHarness(t)
	s := h.mint(h.admin, store.StageFull)
	body := map[string]any{"name": "n", "scopes": []string{"read"}}

	assert.Equal(t, http.StatusForbidden, s.do("POST", "/tokens", body, CSRFHeader, "").Status, "missing CSRF header")
	assert.Equal(t, http.StatusForbidden, s.do("POST", "/tokens", body, CSRFHeader, "wrong").Status, "wrong CSRF header")
	assert.Equal(t, http.StatusCreated, s.do("POST", "/tokens", body).Status, "valid CSRF header")

	// A token needs no CSRF header (it is not ambient browser credentials) but cannot mint tokens.
	tk := h.token(h.admin, []string{"admin"}, nil)
	assert.Equal(t, http.StatusForbidden, tk.do("POST", "/tokens", body).Status)
	assert.Equal(t, http.StatusOK, tk.do("GET", "/config", nil).Status)
}

func TestCookieAttributes(t *testing.T) {
	h := newHarness(t)
	r := h.anon().do("POST", "/auth/login", map[string]string{"username": "ada", "password": pw})
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	cs := (&http.Response{Header: r.Header}).Cookies()
	byName := map[string]*http.Cookie{}
	for _, c := range cs {
		byName[c.Name] = c
	}
	sess, csrf := byName[SessionCookie], byName[CSRFCookie]
	require.NotNil(t, sess)
	require.NotNil(t, csrf)
	assert.True(t, sess.HttpOnly)
	assert.True(t, sess.Secure)
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)
	assert.Equal(t, "/", sess.Path)
	assert.Empty(t, sess.Domain, "__Host- cookies must not set Domain")
	assert.False(t, csrf.HttpOnly, "the dashboard reads the CSRF cookie")
	assert.True(t, csrf.Secure)
	assert.Equal(t, "mfa_enrol_required", r.JSON(t)["status"])
	assert.NotContains(t, string(r.Body), sess.Value, "session secret must only travel in the cookie")
}

func TestBearerGarbageIsUnauthorised(t *testing.T) {
	h := newHarness(t)
	for _, v := range []string{"Bearer", "Bearer x", "Basic abc", "bearer shk_a_b", "Bearer shk_a_b_c_d"} {
		r := h.anon().do("GET", "/config", nil, "Authorization", v)
		assert.Equal(t, http.StatusUnauthorized, r.Status, v)
		assert.Contains(t, r.Header.Get("WWW-Authenticate"), "Bearer")
	}
}

func TestTokenCIDRRestriction(t *testing.T) {
	h := newHarness(t)
	in := h.token(h.admin, []string{"read"}, []string{"127.0.0.0/8", "::1/128"})
	out := h.token(h.admin, []string{"read"}, []string{"192.0.2.0/24"})
	assert.Equal(t, http.StatusOK, in.do("GET", "/config", nil).Status)
	assert.Equal(t, http.StatusUnauthorized, out.do("GET", "/config", nil).Status)
}

func TestFullLoginFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	c := h.anon()

	assert.Equal(t, http.StatusUnauthorized, c.do("GET", "/auth/me", nil).Status)
	bad := c.do("POST", "/auth/login", map[string]string{"username": "ada", "password": wrongAttempt})
	assert.Equal(t, http.StatusUnauthorized, bad.Status)
	assert.Equal(t, "urn:sherlock:problem:invalid_credentials", bad.JSON(t)["type"])

	require.Equal(t, http.StatusOK, c.do("POST", "/auth/login", map[string]string{"username": "ada", "password": pw}).Status)
	c.csrf = cookieValue(t, c, CSRFCookie)

	// Partial session: no data access.
	assert.Equal(t, http.StatusForbidden, c.do("GET", "/config", nil).Status)
	assert.Equal(t, http.StatusForbidden, c.do("GET", "/auth/me", nil).Status)

	en := c.do("POST", "/auth/mfa/enroll", nil)
	require.Equal(t, http.StatusOK, en.Status, string(en.Body))
	secret := en.JSON(t)["secret"].(string)
	assert.Contains(t, en.JSON(t)["otpauth_uri"], "otpauth://totp/")

	// A wrong code is refused and the session stays partial.
	assert.Equal(t, http.StatusUnauthorized, c.do("POST", "/auth/mfa/enroll/confirm", map[string]string{"code": "000000"}).Status)

	done := c.do("POST", "/auth/mfa/enroll/confirm", map[string]string{"code": totpNow(t, secret)})
	require.Equal(t, http.StatusOK, done.Status, string(done.Body))
	c.csrf = cookieValue(t, c, CSRFCookie)

	me := c.do("GET", "/auth/me", nil)
	require.Equal(t, http.StatusOK, me.Status)
	assert.Equal(t, "admin", me.JSON(t)["role"])
	assert.Equal(t, true, me.JSON(t)["mfa_enabled"])
	assert.Equal(t, http.StatusOK, c.do("GET", "/config", nil).Status)

	// Enrolment is closed once complete.
	assert.Equal(t, http.StatusForbidden, c.do("POST", "/auth/mfa/enroll", nil).Status)

	require.Equal(t, http.StatusNoContent, c.do("POST", "/auth/logout", nil).Status)
	assert.Equal(t, http.StatusUnauthorized, c.do("GET", "/auth/me", nil).Status, "logout ends the session")
}

func cookieValue(t *testing.T, s *session, name string) string {
	t.Helper()
	u, err := url.Parse(s.h.srv.URL)
	require.NoError(t, err)
	for _, c := range s.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie", name)
	return ""
}
