package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func adminSession(h *harness) *session { return h.mint(h.admin, store.StageFull) }

func etagOf(t *testing.T, r resp) string {
	t.Helper()
	e := r.Header.Get("ETag")
	require.NotEmpty(t, e)
	return e
}

func newSite(id string) map[string]any {
	return map[string]any{
		"id": id, "hosts": []string{id + ".example.test"}, "tls": map[string]any{"mode": "none"},
		"upstreams": map[string]any{"targets": []string{"127.0.0.1:9"}}, "policy": map[string]any{"mode": "detect"},
	}
}

func TestConfigWriteNeedsAFreshIfMatch(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)

	get := a.do("GET", "/config", nil)
	require.Equal(t, http.StatusOK, get.Status)
	tag := etagOf(t, get)

	assert.Equal(t, http.StatusPreconditionRequired, a.do("POST", "/sites", newSite("blog")).Status, "no If-Match")
	assert.Equal(t, http.StatusPreconditionFailed, a.do("POST", "/sites", newSite("blog"), "If-Match", `"01STALE"`).Status, "stale If-Match")

	ok := a.do("POST", "/sites", newSite("blog"), "If-Match", tag)
	require.Equal(t, http.StatusCreated, ok.Status, string(ok.Body))
	newTag := etagOf(t, ok)
	assert.NotEqual(t, tag, newTag)

	// The old tag is now stale: the second writer must re-read.
	assert.Equal(t, http.StatusPreconditionFailed, a.do("POST", "/sites", newSite("docs"), "If-Match", tag).Status)

	list := a.do("GET", "/sites", nil)
	assert.Equal(t, newTag, list.Header.Get("ETag"))
	assert.Len(t, list.JSON(t)["items"], 2)

	h.plane.mu.Lock()
	defer h.plane.mu.Unlock()
	require.Len(t, h.plane.live.Sites, 2, "the data plane must have been activated with the new site")
}

func TestConfigRejectsUnknownFieldsAndInvalidValues(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/config", nil))

	typo := newSite("blog")
	typo["upstream"] = "x" // misspelled key
	r := a.do("POST", "/sites", typo, "If-Match", tag)
	assert.Equal(t, http.StatusBadRequest, r.Status)
	assert.Contains(t, string(r.Body), "unknown field")

	bad := newSite("Bad Id")
	r = a.do("POST", "/sites", bad, "If-Match", tag)
	require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	errs := r.JSON(t)["errors"].([]any)
	require.NotEmpty(t, errs)
	assert.Equal(t, "/sites/1/id", errs[0].(map[string]any)["path"], "validation errors carry a JSON pointer")

	// The failed attempts changed nothing.
	assert.Equal(t, tag, a.do("GET", "/config", nil).Header.Get("ETag"))
}

func TestValidateEndpointDoesNotApply(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/config", nil))

	r := a.do("POST", "/config/validate", `{"schema_version":1,"sites":[{"id":"x y"}]}`)
	require.Equal(t, http.StatusOK, r.Status)
	assert.Equal(t, false, r.JSON(t)["valid"])
	assert.NotEmpty(t, r.JSON(t)["errors"])
	assert.Equal(t, tag, a.do("GET", "/config", nil).Header.Get("ETag"))
}

func TestPatchSiteIsAMergePatch(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/sites/shop", nil))

	r := a.do("PATCH", "/sites/shop", `{"policy":{"mode":"block"}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	got := a.do("GET", "/sites/shop", nil).JSON(t)
	assert.Equal(t, "block", got["policy"].(map[string]any)["mode"])
	assert.Equal(t, []any{"shop.example.test"}, got["hosts"], "untouched fields survive")

	tag = etagOf(t, a.do("GET", "/sites/shop", nil))
	assert.Equal(t, http.StatusUnprocessableEntity,
		a.do("PATCH", "/sites/shop", `{"id":"other"}`, "If-Match", tag, "Content-Type", "application/merge-patch+json").Status, "id is immutable")
	assert.Equal(t, http.StatusUnprocessableEntity,
		a.do("PATCH", "/sites/shop", `{"nonsense":1}`, "If-Match", tag, "Content-Type", "application/merge-patch+json").Status, "unknown field")
	assert.Equal(t, http.StatusNotFound,
		a.do("PATCH", "/sites/ghost", `{}`, "If-Match", tag, "Content-Type", "application/merge-patch+json").Status)
}

func TestEndpointsAndEffectivePolicy(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/config", nil))

	ep := map[string]any{"id": "login", "match": map[string]any{"path": "/login", "methods": []string{"POST"}}, "policy": map[string]any{"mode": "block", "waf": map[string]any{"paranoia_level": 3}}}
	r := a.do("POST", "/sites/shop/endpoints", ep, "If-Match", tag)
	require.Equal(t, http.StatusCreated, r.Status, string(r.Body))
	assert.Equal(t, http.StatusConflict, a.do("POST", "/sites/shop/endpoints", ep, "If-Match", etagOf(t, r)).Status, "duplicate id")

	eff := a.do("GET", "/sites/shop/effective-policy?path=/login&method=POST", nil)
	require.Equal(t, http.StatusOK, eff.Status, string(eff.Body))
	body := eff.JSON(t)
	assert.Equal(t, "login", body["matched_endpoint"])
	pol := body["policy"].(map[string]any)
	assert.Equal(t, "block", pol["mode"])
	assert.EqualValues(t, 3, pol["waf"].(map[string]any)["paranoia_level"])
	assert.Equal(t, "endpoint:login", body["sources"].(map[string]any)["waf.paranoia_level"])

	other := a.do("GET", "/sites/shop/effective-policy?path=/login&method=GET", nil).JSON(t)
	assert.Nil(t, other["matched_endpoint"], "the POST-only override must not apply to GET")
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/sites/shop/effective-policy?path=login", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/sites/ghost/effective-policy", nil).Status)

	tag = etagOf(t, a.do("GET", "/sites/shop/endpoints", nil))
	assert.Equal(t, http.StatusOK, a.do("DELETE", "/sites/shop/endpoints/login", nil, "If-Match", tag).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/sites/shop/endpoints/login", nil).Status)
}

func TestVersionsAndRollback(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	first := etagOf(t, a.do("GET", "/config", nil))
	firstID := strings.Trim(first, `"`)

	r := a.do("POST", "/sites", newSite("blog"), "If-Match", first)
	require.Equal(t, http.StatusCreated, r.Status)

	vs := a.do("GET", "/config/versions", nil).JSON(t)["items"].([]any)
	require.Len(t, vs, 2)
	assert.NotEmpty(t, vs[0].(map[string]any)["diff"], "the newer version records what changed")

	detail := a.do("GET", "/config/versions/"+firstID, nil)
	require.Equal(t, http.StatusOK, detail.Status)
	assert.Len(t, detail.JSON(t)["snapshot"].(map[string]any)["sites"], 1)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/config/versions/nope", nil).Status)

	head := etagOf(t, r)
	assert.Equal(t, http.StatusPreconditionRequired, a.do("POST", "/config/versions/"+firstID+"/rollback", nil).Status)
	rb := a.do("POST", "/config/versions/"+firstID+"/rollback", nil, "If-Match", head)
	require.Equal(t, http.StatusOK, rb.Status, string(rb.Body))
	assert.Equal(t, "rollback", rb.JSON(t)["source"])
	assert.Len(t, a.do("GET", "/sites", nil).JSON(t)["items"], 1)

	// Pagination: a page of one has a cursor that yields the next.
	p1 := a.do("GET", "/config/versions?limit=1", nil).JSON(t)
	cur, _ := p1["next_cursor"].(string)
	require.NotEmpty(t, cur)
	p2 := a.do("GET", "/config/versions?limit=1&cursor="+cur, nil).JSON(t)
	assert.NotEqual(t, p1["items"].([]any)[0].(map[string]any)["id"], p2["items"].([]any)[0].(map[string]any)["id"])
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/config/versions?cursor=!!!", nil).Status)
}

func TestUserManagement(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)

	assert.Equal(t, http.StatusBadRequest, a.do("POST", "/users", map[string]any{"username": "bo", "password": pw, "role": "viewer"}).Status, "short username")
	assert.Equal(t, http.StatusBadRequest, a.do("POST", "/users", map[string]any{"username": "bobby", "password": "short", "role": "viewer"}).Status, "weak password")
	assert.Equal(t, http.StatusBadRequest, a.do("POST", "/users", map[string]any{"username": "bobby", "password": pw, "role": "root"}).Status, "unknown role")
	made := a.do("POST", "/users", map[string]any{"username": "bobby", "password": pw, "role": "viewer"})
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))
	assert.NotContains(t, string(made.Body), "password", "responses never carry credential material")
	assert.Equal(t, http.StatusConflict, a.do("POST", "/users", map[string]any{"username": "bobby", "password": pw, "role": "viewer"}).Status)
	id := made.JSON(t)["id"].(string)

	// Changing a password or role ends that user's sessions.
	bobSession := h.mint(store.User{ID: id}, store.StageFull)
	require.Equal(t, http.StatusOK, bobSession.do("GET", "/auth/me", nil).Status)
	require.Equal(t, http.StatusOK, a.do("PATCH", "/users/"+id, map[string]any{"role": "admin"}).Status)
	assert.Equal(t, http.StatusUnauthorized, bobSession.do("GET", "/auth/me", nil).Status, "role change must revoke sessions")

	// A new admin exists, so the original may be demoted — but not the last one.
	require.Equal(t, http.StatusOK, a.do("PATCH", "/users/"+h.admin.ID, map[string]any{"disabled": true}).Status)
	only := h.mint(store.User{ID: id, Role: "admin"}, store.StageFull)
	assert.Equal(t, http.StatusConflict, only.do("PATCH", "/users/"+id, map[string]any{"disabled": true}).Status, "last enabled admin")
	assert.Equal(t, http.StatusConflict, only.do("PATCH", "/users/"+id, map[string]any{"role": "viewer"}).Status, "last enabled admin")
	assert.Equal(t, http.StatusConflict, only.do("DELETE", "/users/"+id, nil).Status, "cannot delete yourself")
	assert.Equal(t, http.StatusNotFound, only.do("DELETE", "/users/nope", nil).Status)
	assert.Equal(t, http.StatusNoContent, only.do("DELETE", "/users/"+h.admin.ID, nil).Status)
}

func TestResetMFAClearsEnrolment(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	require.NoError(t, h.st.Tx(h.t.Context(), func(ctx context.Context, tx store.Tx) error {
		return tx.SetUserMFA(ctx, h.view.ID, "", true)
	}))
	r := a.do("POST", "/users/"+h.view.ID+"/reset-mfa", nil)
	require.Equal(t, http.StatusNoContent, r.Status)
	users := a.do("GET", "/users", nil).JSON(t)["items"].([]any)
	for _, u := range users {
		if u.(map[string]any)["id"] == h.view.ID {
			assert.Equal(t, false, u.(map[string]any)["mfa_enabled"])
		}
	}
	assert.Equal(t, http.StatusNotFound, a.do("POST", "/users/nope/reset-mfa", nil).Status)
}

func TestTokenLifecycleAndOwnership(t *testing.T) {
	h := newHarness(t)
	admin, viewer := adminSession(h), h.mint(h.view, store.StageFull)

	bad := admin.do("POST", "/tokens", map[string]any{"name": "x", "scopes": []string{"root"}})
	assert.Equal(t, http.StatusBadRequest, bad.Status)
	assert.Equal(t, http.StatusBadRequest, admin.do("POST", "/tokens", map[string]any{"name": " ", "scopes": []string{"read"}}).Status)
	assert.Equal(t, http.StatusBadRequest, admin.do("POST", "/tokens", map[string]any{"name": "x", "scopes": []string{"read"}, "cidrs": []string{"nope"}}).Status)

	made := admin.do("POST", "/tokens", map[string]any{"name": "ci", "scopes": []string{"read"}})
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))
	secret := made.JSON(t)["token"].(string)
	id := made.JSON(t)["id"].(string)
	assert.True(t, strings.HasPrefix(secret, "shk_"+id+"_"))

	listed := admin.do("GET", "/tokens", nil)
	assert.NotContains(t, string(listed.Body), secret, "the secret is shown once, at creation")
	assert.Len(t, listed.JSON(t)["items"], 1)
	assert.Empty(t, viewer.do("GET", "/tokens", nil).JSON(t)["items"], "a viewer sees only their own tokens")

	// IDOR: another user's token looks nonexistent.
	assert.Equal(t, http.StatusNotFound, viewer.do("DELETE", "/tokens/"+id, nil).Status)
	assert.Equal(t, http.StatusOK, h.anon().do("GET", "/config", nil, "Authorization", "Bearer "+secret).Status, "token works until revoked")
	assert.Equal(t, http.StatusNoContent, admin.do("DELETE", "/tokens/"+id, nil).Status)
	assert.Equal(t, http.StatusUnauthorized, h.anon().do("GET", "/config", nil, "Authorization", "Bearer "+secret).Status, "revoked")
}

func TestAuditTrailCoversChangesAndVerifies(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/config", nil))
	require.Equal(t, http.StatusCreated, a.do("POST", "/sites", newSite("blog"), "If-Match", tag).Status)
	require.Equal(t, http.StatusCreated, a.do("POST", "/users", map[string]any{"username": "bobby", "password": pw, "role": "viewer"}).Status)
	tokenResp := a.do("POST", "/tokens", map[string]any{"name": "ci", "scopes": []string{"read"}})
	secret := tokenResp.JSON(t)["token"].(string)
	// A denied request is audited too.
	h.mint(h.view, store.StageFull).do("GET", "/audit", nil)

	r := a.do("GET", "/audit", nil)
	require.Equal(t, http.StatusOK, r.Status)
	actions := map[string]bool{}
	for _, it := range r.JSON(t)["items"].([]any) {
		actions[it.(map[string]any)["action"].(string)] = true
	}
	for _, want := range []string{"config.apply", "user.create", "token.create", "auth.denied"} {
		assert.True(t, actions[want], want)
	}
	assert.NotContains(t, string(r.Body), secret, "audit never records a token secret")
	assert.NotContains(t, string(r.Body), pw)

	rep, err := audit.Verify(h.t.Context(), h.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem)

	info := a.do("GET", "/system/info", nil).JSON(t)
	assert.Equal(t, "sqlite", info["database"])
	assert.Equal(t, true, info["ready"])
	assert.Equal(t, "4.25.0", info["crs_version"])
	assert.EqualValues(t, rep.Head.Seq, info["audit_head"].(map[string]any)["seq"])
	assert.Equal(t, rep.Head.Hash, info["audit_head"].(map[string]any)["hash"])
}

func TestEventsEndpoints(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	require.NoError(t, h.st.Tx(h.t.Context(), func(ctx context.Context, tx store.Tx) error {
		for i, act := range []string{"block", "log"} {
			if err := tx.InsertEvent(ctx, store.EventRow{ID: "01EV0000000000000000000" + string(rune('A'+i)), TS: timeAt(i), SiteID: "shop", Action: act, ClientIP: "203.0.113.5", Body: []byte(`{"schema":"sherlock.event.v1","action":"` + act + `"}`)}); err != nil {
				return err
			}
		}
		return nil
	}))
	all := a.do("GET", "/events", nil).JSON(t)["items"].([]any)
	assert.Len(t, all, 2)
	blocked := a.do("GET", "/events?action=block", nil).JSON(t)["items"].([]any)
	require.Len(t, blocked, 1)
	assert.Equal(t, "block", blocked[0].(map[string]any)["action"])
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/events?ip=not-an-ip", nil).Status)
	assert.Equal(t, http.StatusOK, a.do("GET", "/events/01EV0000000000000000000A", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/events/missing", nil).Status)
	assert.Len(t, a.do("GET", "/events?site=other", nil).JSON(t)["items"], 0)
}

func TestMalformedBodiesAreBadRequests(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	for name, body := range map[string]string{"empty": "", "truncated": `{"name":`, "wrong type": `{"name":1,"scopes":"read"}`} {
		r := a.do("POST", "/tokens", body)
		assert.Equal(t, http.StatusBadRequest, r.Status, name)
		assert.Equal(t, "application/problem+json", r.Header.Get("Content-Type"), name)
	}
	huge := `{"name":"` + strings.Repeat("a", 5<<20) + `"}`
	assert.Equal(t, http.StatusBadRequest, a.do("POST", "/tokens", huge).Status, "bodies over the limit are refused")
}

func TestLoginThrottlingReturns429WithRetryAfter(t *testing.T) {
	h := newHarness(t)
	c := h.anon()
	var last resp
	for range 7 {
		last = c.do("POST", "/auth/login", map[string]string{"username": "ada", "password": "wrong wrong wrong"})
	}
	assert.Equal(t, http.StatusTooManyRequests, last.Status)
	assert.NotEmpty(t, last.Header.Get("Retry-After"))
	assert.NotEmpty(t, last.JSON(t)["retry_after_seconds"])
}
