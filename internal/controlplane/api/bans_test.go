package api

import (
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
)

func TestBanLifecycle(t *testing.T) {
	acl.Bans.Replace(nil)
	t.Cleanup(func() { acl.Bans.Replace(nil) })
	h := newHarness(t)
	a := adminSession(h)
	target := netip.MustParseAddr("203.0.113.77")

	bad := map[string]map[string]any{
		"no duration":  {"ip": "203.0.113.77"},
		"too short":    {"ip": "203.0.113.77", "duration_seconds": 10},
		"too long":     {"ip": "203.0.113.77", "duration_seconds": 40 * 24 * 3600},
		"not an ip":    {"ip": "nope", "duration_seconds": 600},
		"a range":      {"ip": "203.0.113.0/24", "duration_seconds": 600},
		"unknown site": {"ip": "203.0.113.77", "duration_seconds": 600, "site_id": "ghost"},
	}
	for name, body := range bad {
		assert.Equal(t, http.StatusBadRequest, a.do("POST", "/bans", body).Status, name)
	}

	made := a.do("POST", "/bans", map[string]any{"ip": "203.0.113.77", "duration_seconds": 3600, "reason": "scanner"})
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))
	id := made.JSON(t)["id"].(string)
	assert.Equal(t, "manual", made.JSON(t)["source"])
	_, active := acl.Bans.Active(target, "shop", time.Now())
	assert.True(t, active, "a created ban is enforced immediately, without a reload")

	siteBan := a.do("POST", "/bans", map[string]any{"ip": "203.0.113.78", "duration_seconds": 600, "site_id": "shop"})
	require.Equal(t, http.StatusCreated, siteBan.Status, string(siteBan.Body))
	_, other := acl.Bans.Active(netip.MustParseAddr("203.0.113.78"), "another", time.Now())
	assert.False(t, other, "a site-scoped ban applies to that site only")

	list := a.do("GET", "/bans", nil).JSON(t)["items"].([]any)
	assert.Len(t, list, 2)
	assert.Len(t, h.mint(h.view, "full").do("GET", "/bans", nil).JSON(t)["items"], 2, "viewers can see bans")
	assert.Equal(t, http.StatusForbidden, h.mint(h.view, "full").do("POST", "/bans", map[string]any{"ip": "203.0.113.5", "duration_seconds": 600}).Status, "but not create them")

	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/bans/"+id, nil).Status)
	_, active = acl.Bans.Active(target, "shop", time.Now())
	assert.False(t, active, "lifting a ban takes effect immediately")
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/bans/"+id, nil).Status)
	assert.Len(t, a.do("GET", "/bans", nil).JSON(t)["items"], 1)
}

func TestCannotBanYourself(t *testing.T) {
	acl.Bans.Replace(nil)
	t.Cleanup(func() { acl.Bans.Replace(nil) })
	h := newHarness(t)
	a := adminSession(h)
	r := a.do("POST", "/bans", map[string]any{"ip": "127.0.0.1", "duration_seconds": 600})
	assert.Equal(t, http.StatusConflict, r.Status, "the test client connects from 127.0.0.1")
	assert.Contains(t, string(r.Body), "ban the address you are using")
	r = a.do("POST", "/bans", map[string]any{"ip": "::ffff:127.0.0.1", "duration_seconds": 600})
	assert.Equal(t, http.StatusConflict, r.Status, "the mapped form is the same address")
}

func TestFeedsStatusDefaultsToEmpty(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	assert.Empty(t, a.do("GET", "/feeds/status", nil).JSON(t)["items"])
}
