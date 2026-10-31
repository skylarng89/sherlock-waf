package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/policy/ratelimit"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/updater"
)

// countingLimits counts requests per key and never resets, so the tests do not
// depend on the wall clock or on a sliding window crossing a boundary.
type countingLimits struct {
	mu    sync.Mutex
	hits  map[string]int
	limit map[string]int
}

func newCountingLimits() *countingLimits {
	return &countingLimits{hits: map[string]int{}, limit: map[string]int{}}
}

func (c *countingLimits) Allow(_ context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits[key]++
	c.limit[key] = limit
	if c.hits[key] > limit {
		return ratelimit.Result{Allowed: false, RetryAfter: window}, nil
	}
	return ratelimit.Result{Allowed: true, Remaining: limit - c.hits[key]}, nil
}

func (c *countingLimits) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.hits))
	for k := range c.hits {
		out = append(out, k)
	}
	return out
}

func TestTokenLifetimeIsCappedAndDefaulted(t *testing.T) {
	h := newHarness(t)
	admin := adminSession(h)
	h.auth.TokenMaxLifetime = auth.DefaultTokenMaxLifetime

	tooLong := map[string]any{"name": "ci", "scopes": []string{"read"}, "expires_at": time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	r := admin.do("POST", "/tokens", tooLong)
	require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	errs, ok := r.JSON(t)["errors"].([]any)
	require.True(t, ok, string(r.Body))
	require.Len(t, errs, 1)
	assert.Equal(t, "/expires_at", errs[0].(map[string]any)["path"], "the field error points at expires_at")

	defaulted := admin.do("POST", "/tokens", map[string]any{"name": "ci", "scopes": []string{"read"}})
	require.Equal(t, http.StatusCreated, defaulted.Status, string(defaulted.Body))
	exp, err := time.Parse(time.RFC3339Nano, defaulted.JSON(t)["expires_at"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(auth.DefaultTokenMaxLifetime), exp, time.Minute, "omitted expiry becomes now plus the maximum")
}

func TestTokenCountPerUserIsCappedOverHTTP(t *testing.T) {
	h := newHarness(t)
	admin := adminSession(h)
	body := map[string]any{"name": "t", "scopes": []string{"read"}}
	for i := range auth.MaxTokensPerUser {
		require.Equal(t, http.StatusCreated, admin.do("POST", "/tokens", body).Status, "token %d", i)
	}
	r := admin.do("POST", "/tokens", body)
	require.Equal(t, http.StatusConflict, r.Status, string(r.Body))
	assert.Contains(t, r.JSON(t)["detail"], fmt.Sprintf("%d API tokens", auth.MaxTokensPerUser))
}

func TestUpdateApplyRefusesAPITokens(t *testing.T) {
	if updater.InContainer() {
		t.Skip("apply is refused inside containers")
	}
	fu := &fakeUpdates{}
	applied := false
	fu.applyFn = func() (updater.Result, bool, error) {
		applied = true
		return updater.Result{From: "0.4.0", To: "0.5.0"}, true, nil
	}
	h := newHarnessWith(t, harnessOpts{update: fu})
	tk := h.token(h.admin, []string{"admin"}, nil)

	r := tk.do("POST", "/system/update/apply", nil)
	require.Equal(t, http.StatusForbidden, r.Status, "an admin-scoped token cannot replace the binary")
	assert.Contains(t, r.JSON(t)["detail"], "browser session")
	assert.False(t, applied, "the update service must not be reached")

	ok := adminSession(h).do("POST", "/system/update/apply", nil)
	require.Equal(t, http.StatusOK, ok.Status, "a session with system:update still applies")
	assert.True(t, applied)
}

func TestTokenFailuresAreRateLimitedBeforeLookup(t *testing.T) {
	h := newHarness(t)
	valid := h.token(h.admin, []string{"read"}, nil)
	bad := h.anon()
	bad.bearer = "shk_01NOPE0000000000000000000A_definitely-wrong"
	for i := range 10 {
		require.Equal(t, http.StatusUnauthorized, bad.do("GET", "/auth/me", nil).Status, "failure %d", i)
	}
	r := bad.do("GET", "/auth/me", nil)
	require.Equal(t, http.StatusTooManyRequests, r.Status, "the eleventh failure from this address is refused without a lookup")
	assert.NotEmpty(t, r.Header.Get("Retry-After"))
	assert.Equal(t, http.StatusTooManyRequests, valid.do("GET", "/auth/me", nil).Status, "a valid token from the same address waits too")
}

func TestPrincipalRequestLimitIs300PerMinute(t *testing.T) {
	lim := newCountingLimits()
	h := newHarnessWith(t, harnessOpts{limits: lim})
	admin := adminSession(h)
	for i := range DefaultPrincipalRequestsPerMinute {
		require.Equal(t, http.StatusOK, admin.do("GET", "/auth/me", nil).Status, "request %d", i+1)
	}
	r := admin.do("GET", "/auth/me", nil)
	require.Equal(t, http.StatusTooManyRequests, r.Status, string(r.Body))
	assert.NotEmpty(t, r.Header.Get("Retry-After"))
	assert.Equal(t, "throttled", r.JSON(t)["type"].(string)[len("urn:sherlock:problem:"):])
	assert.Equal(t, http.StatusOK, h.mint(h.view, store.StageFull).do("GET", "/auth/me", nil).Status, "another principal has its own budget")
}

func TestPrincipalRequestLimitIsConfigurable(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{limits: newCountingLimits(), principalLimit: 5})
	admin := adminSession(h)
	for i := range 5 {
		require.Equal(t, http.StatusOK, admin.do("GET", "/auth/me", nil).Status, "request %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, admin.do("GET", "/auth/me", nil).Status, "the configured budget, not the default, applies")
}

func TestAnonymousRequestLimitIsPerIPOnPublicOperations(t *testing.T) {
	lim := newCountingLimits()
	h := newHarnessWith(t, harnessOpts{limits: lim})
	anon := h.anon()
	for range anonymousRequestsPerMinute {
		require.Equal(t, http.StatusOK, anon.do("GET", "/setup/status", nil).Status)
	}
	require.Equal(t, http.StatusTooManyRequests, anon.do("GET", "/setup/status", nil).Status)
	assert.Equal(t, anonymousRequestsPerMinute, lim.limit["anon:127.0.0.1"], "the anonymous budget is keyed on the client address")
}

func TestUnauthenticatedRequestsDoNotSpendAVictimsBudget(t *testing.T) {
	lim := newCountingLimits()
	h := newHarnessWith(t, harnessOpts{limits: lim})
	attacker := h.anon()
	for i := range 400 {
		require.Equal(t, http.StatusUnauthorized, attacker.do("GET", "/auth/me", nil).Status, "request %d", i+1)
	}
	for _, k := range lim.keys() {
		assert.NotContains(t, k, "anon:", "a protected operation is not an anonymous public one")
		assert.NotContains(t, k, h.admin.ID, "the admin was never charged for the attacker")
	}
	assert.Equal(t, http.StatusOK, adminSession(h).do("GET", "/auth/me", nil).Status)
}
