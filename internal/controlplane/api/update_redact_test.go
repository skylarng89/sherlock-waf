package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/updater"
)

type fakeUpdates struct {
	checks  atomic.Int32
	status  updater.Status
	applyFn func() (updater.Result, bool, error)
}

func (f *fakeUpdates) Check(context.Context) (updater.Status, error) {
	f.checks.Add(1)
	return f.status, nil
}
func (f *fakeUpdates) Apply(context.Context) (updater.Result, bool, error) { return f.applyFn() }
func (f *fakeUpdates) Staged() (string, bool)                              { return "", false }

func TestUpdateEndpointsPermissionsAuditAndErrors(t *testing.T) {
	if updater.InContainer() {
		t.Skip("apply is refused inside containers")
	}
	fu := &fakeUpdates{status: updater.Status{Current: "0.4.0", Latest: "0.5.0", Available: true, CRS: "4.25.0"}}
	h := newHarnessWith(t, harnessOpts{update: fu})
	admin, viewer := adminSession(h), h.mint(h.view, store.StageFull)

	st := viewer.do("GET", "/system/update", nil)
	require.Equal(t, http.StatusOK, st.Status, string(st.Body))
	assert.Equal(t, "0.5.0", st.JSON(t)["latest"])
	admin.do("GET", "/system/update", nil)
	assert.EqualValues(t, 1, fu.checks.Load(), "a successful check is cached")

	fu.applyFn = func() (updater.Result, bool, error) {
		return updater.Result{From: "0.4.0", To: "0.5.0"}, true, nil
	}
	assert.Equal(t, http.StatusForbidden, viewer.do("POST", "/system/update/apply", nil).Status, "readers cannot apply")
	assert.Equal(t, http.StatusForbidden, h.token(h.admin, []string{"write"}, nil).do("POST", "/system/update/apply", nil).Status, "the write scope cannot apply")
	assert.Equal(t, http.StatusUnauthorized, h.anon().do("POST", "/system/update/apply", nil).Status)

	ok := admin.do("POST", "/system/update/apply", nil)
	require.Equal(t, http.StatusOK, ok.Status, string(ok.Body))
	assert.Equal(t, "staged", ok.JSON(t)["state"])

	for err, want := range map[error]int{
		updater.ErrChecksum:  http.StatusBadGateway,
		updater.ErrDowngrade: http.StatusUnprocessableEntity,
		updater.ErrUpToDate:  http.StatusConflict,
		errors.New("dial tcp 10.1.2.3:443: refused (secret-host.internal)"): http.StatusBadGateway,
	} {
		fu.applyFn = func() (updater.Result, bool, error) { return updater.Result{}, false, err }
		r := admin.do("POST", "/system/update/apply", nil)
		assert.Equal(t, want, r.Status, err.Error())
		assert.NotContains(t, string(r.Body), "secret-host", "internal detail never reaches the client")
		assert.NotContains(t, string(r.Body), "10.1.2.3")
	}

	actions := map[string]int{}
	for _, it := range admin.do("GET", "/audit", nil).JSON(t)["items"].([]any) {
		actions[it.(map[string]any)["action"].(string)]++
	}
	assert.Equal(t, 1, actions["system.update"])
	assert.Equal(t, 4, actions["system.update_failed"], "failed applies are audited too")
	assert.NotZero(t, actions["auth.denied"])
}

func TestUpdateDisabledWithoutService(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, http.StatusNotImplemented, adminSession(h).do("GET", "/system/update", nil).Status)
	assert.Equal(t, http.StatusNotImplemented, adminSession(h).do("POST", "/system/update/apply", nil).Status)
}

func TestListBackups(t *testing.T) {
	h := newHarness(t)
	r := h.mint(h.view, store.StageFull).do("GET", "/system/backups", nil)
	require.Equal(t, http.StatusOK, r.Status)
	assert.Empty(t, r.JSON(t)["items"])
}

const hash = "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"

func storedHash(t *testing.T, h *harness, site string) string {
	t.Helper()
	_, root, err := h.cfg.Current(t.Context())
	require.NoError(t, err)
	for _, s := range root.Sites {
		if s.ID == site && s.Policy.ACL != nil && s.Policy.ACL.PasswordGate != nil {
			return s.Policy.ACL.PasswordGate.PasswordHash
		}
	}
	return ""
}

func TestPasswordHashIsRedactedAndPreserved(t *testing.T) {
	h := newHarness(t)
	a, viewer := adminSession(h), h.mint(h.view, store.StageFull)
	fresh := func() string { return a.do("GET", "/config", nil).Header.Get("ETag") }

	site := map[string]any{
		"id": "gated", "hosts": []string{"gated.example.test"}, "tls": map[string]any{"mode": "none"},
		"upstreams": map[string]any{"targets": []string{"127.0.0.1:9"}},
		"policy":    map[string]any{"mode": "detect", "acl": map[string]any{"password_gate": map[string]any{"enabled": true, "username": "u", "password_hash": hash}}},
		"endpoints": []any{map[string]any{"id": "e", "match": map[string]any{"path": "/e"}, "policy": map[string]any{"acl": map[string]any{"password_gate": map[string]any{"enabled": true, "username": "u2", "password_hash": hash}}}}},
	}
	require.Equal(t, http.StatusCreated, a.do("POST", "/sites", site, "If-Match", fresh()).Status)
	require.Equal(t, hash, storedHash(t, h, "gated"))
	d := a.do("PUT", "/defaults", map[string]any{"acl": map[string]any{"password_gate": map[string]any{"enabled": false, "username": "d", "password_hash": hash}}}, "If-Match", fresh())
	require.Equal(t, http.StatusOK, d.Status, string(d.Body))

	versions := a.do("GET", "/config/versions", nil).JSON(t)["items"].([]any)
	vid := versions[0].(map[string]any)["id"].(string)
	for _, who := range []*session{viewer, a, h.token(h.view, []string{"read"}, nil)} {
		for _, path := range []string{"/config", "/sites", "/sites/gated", "/sites/gated/endpoints", "/sites/gated/endpoints/e", "/defaults", "/config/versions/" + vid, "/sites/gated/effective-policy"} {
			r := who.do("GET", path, nil)
			require.Equal(t, http.StatusOK, r.Status, path)
			assert.NotContains(t, string(r.Body), "argon2id", "%s must not expose the hash", path)
			if path != "/sites/gated/effective-policy" {
				assert.Contains(t, string(r.Body), `redacted`, path) // Go escapes < and > in JSON; clients decode "<redacted>"
			}
		}
	}
	// Reading never mutates the live configuration.
	assert.Equal(t, hash, storedHash(t, h, "gated"))

	// A read-modify-write that echoes the placeholder keeps the stored hash.
	cfg := viewer.do("GET", "/config", nil)
	etag := cfg.Header.Get("ETag")
	put := a.do("PUT", "/config", cfg.Body, "If-Match", etag)
	require.Equal(t, http.StatusOK, put.Status, string(put.Body))
	assert.Equal(t, hash, storedHash(t, h, "gated"), "PUT /config with the placeholder keeps the stored hash")

	// Omitting the field also keeps it.
	got := a.do("GET", "/sites/gated", nil)
	site2 := got.JSON(t)
	delete(site2["policy"].(map[string]any)["acl"].(map[string]any)["password_gate"].(map[string]any), "password_hash")
	delete(site2, "endpoints")
	patch := a.do("PATCH", "/sites/gated", map[string]any{"policy": site2["policy"]}, "If-Match", fresh())
	require.Equal(t, http.StatusOK, patch.Status, string(patch.Body))
	assert.Equal(t, hash, storedHash(t, h, "gated"), "an omitted hash is not cleared")

	// PATCH carrying the placeholder keeps it too.
	patch = a.do("PATCH", "/sites/gated", map[string]any{"policy": map[string]any{"acl": map[string]any{"password_gate": map[string]any{"password_hash": config.RedactedPlaceholder, "username": "renamed"}}}}, "If-Match", fresh())
	require.Equal(t, http.StatusOK, patch.Status, string(patch.Body))
	assert.Equal(t, hash, storedHash(t, h, "gated"))

	// A real new hash replaces it.
	newHash := strings.Replace(hash, "aGFzaGhhc2hoYXNoaGFzaA", "bmV3aGFzaG5ld2hhc2g", 1)
	patch = a.do("PATCH", "/sites/gated", map[string]any{"policy": map[string]any{"acl": map[string]any{"password_gate": map[string]any{"password_hash": newHash}}}}, "If-Match", fresh())
	require.Equal(t, http.StatusOK, patch.Status, string(patch.Body))
	assert.Equal(t, newHash, storedHash(t, h, "gated"))

	// The placeholder cannot smuggle a hash across sites, and never validates as a hash.
	other := map[string]any{
		"id": "other", "hosts": []string{"other.example.test"}, "tls": map[string]any{"mode": "none"},
		"upstreams": map[string]any{"targets": []string{"127.0.0.1:9"}},
		"policy":    map[string]any{"acl": map[string]any{"password_gate": map[string]any{"enabled": true, "username": "u", "password_hash": config.RedactedPlaceholder}}},
	}
	r := a.do("POST", "/sites", other, "If-Match", fresh())
	assert.Equal(t, http.StatusUnprocessableEntity, r.Status, "a new site cannot reuse another site's hash through the placeholder")
	assert.NotContains(t, string(r.Body), "argon2id$v=19")
}

func TestTestUpstreamRefusesMetadataAndLinkLocal(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	for _, target := range []string{"169.254.169.254:80", "[fe80::1]:80", "0.0.0.0:80"} {
		r := a.do("POST", "/system/test-upstream", map[string]any{"target": target})
		require.Equal(t, http.StatusOK, r.Status, target)
		body := r.JSON(t)
		assert.Equal(t, false, body["reachable"], target)
		assert.Equal(t, "blocked", body["error"], target)
	}
}

func TestAdminCanResetAPasswordThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	victim := h.mint(h.view, store.StageFull)
	require.Equal(t, http.StatusOK, victim.do("GET", "/auth/me", nil).Status)

	r := a.do("PATCH", "/users/"+h.view.ID, map[string]any{"password": "another long passphrase"})
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	assert.Equal(t, http.StatusUnauthorized, victim.do("GET", "/auth/me", nil).Status, "a password change ends the user's sessions")
	assert.Equal(t, http.StatusBadRequest, a.do("PATCH", "/users/"+h.view.ID, map[string]any{"password": "password1234"}).Status, "weak passwords are refused")

	audit := a.do("GET", "/audit", nil)
	assert.Contains(t, string(audit.Body), "credentials_changed")
	assert.NotContains(t, string(audit.Body), "another long passphrase")
}
