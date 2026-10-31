package auth

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

func auditRows(t *testing.T, st store.Store, action string) []store.AuditEntry {
	t.Helper()
	var out []store.AuditEntry
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		entries, err := tx.ListAudit(ctx, 0, 1000)
		for _, e := range entries {
			if e.Action == action {
				out = append(out, e)
			}
		}
		return err
	}))
	return out
}

func TestAccountLockIsAuditedOncePerLock(t *testing.T) {
	e := newEnv(t, RoleViewer)
	for i := range 5 {
		e.clk.advance(13 * time.Second)
		_, err := e.svc.Login(t.Context(), "10.1.0.1", "ua", "ada", "wrong password!!")
		require.ErrorIs(t, err, ErrInvalidCredentials, "attempt %d", i)
	}
	assert.Len(t, auditRows(t, e.st, "auth.account_locked"), 1, "the fifth failure starts the first lock")

	for range 3 {
		_, err := e.svc.Login(t.Context(), "10.1.0.2", "ua", "ada", testPassword)
		require.Error(t, err)
	}
	assert.Len(t, auditRows(t, e.st, "auth.account_locked"), 1, "attempts during a lock do not add lock rows")

	e.clk.advance(2 * time.Minute)
	_, err := e.svc.Login(t.Context(), "10.1.0.3", "ua", "ada", "wrong password!!")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Len(t, auditRows(t, e.st, "auth.account_locked"), 2, "the next lock is a new event")
}

func TestUsernameCeilingDoesNotLetOneClientLockOutTheAccountFaster(t *testing.T) {
	e := newEnv(t, RoleViewer)
	// One client can still make only 5 attempts a minute at the same username.
	var te *ThrottledError
	for i := range 6 {
		_, err := e.svc.Login(t.Context(), "10.2.0.1", "ua", "ada", "wrong password!!")
		if i < 5 {
			require.ErrorIs(t, err, ErrInvalidCredentials)
		} else {
			require.ErrorAs(t, err, &te)
		}
	}
}

func TestTokenFailuresAreThrottledBeforeLookupAndCoalesced(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	ctx := t.Context()
	ip := netip.MustParseAddr("10.3.0.1")
	created, err := e.svc.CreateToken(ctx, e.uid, "ci", []string{ScopeRead}, nil, time.Time{})
	require.NoError(t, err)

	bad := "shk_" + created.Record.ID + "_wrongsecret"
	for range tokenFailLimit {
		_, err := e.svc.AuthenticateToken(ctx, bad, ip)
		require.ErrorIs(t, err, ErrUnauthenticated)
	}
	// Refused before the lookup: even the correct secret from this IP now gets 429.
	_, err = e.svc.AuthenticateToken(ctx, created.Secret, ip)
	var te *ThrottledError
	require.ErrorAs(t, err, &te, "a blocked address is refused even with a valid token")
	assert.Positive(t, te.RetryAfter)

	rows := auditRows(t, e.st, "auth.token_failed")
	require.Len(t, rows, 1, "the first failure writes one row; the rest of the window is coalesced")
	assert.Contains(t, string(rows[0].Details), `"failures":1`)

	// Another client is unaffected.
	_, err = e.svc.AuthenticateToken(ctx, created.Secret, netip.MustParseAddr("10.3.0.2"))
	require.NoError(t, err)

	e.clk.advance(tokenFailWindow + time.Second)
	_, err = e.svc.AuthenticateToken(ctx, bad, ip)
	require.ErrorIs(t, err, ErrUnauthenticated)
	rows = auditRows(t, e.st, "auth.token_failed")
	require.Len(t, rows, 2, "the next window writes one row carrying the coalesced count")
	// The audit list is newest first.
	assert.Contains(t, string(rows[0].Details), `"failures":10`, "nine coalesced failures plus this one")
	assert.Contains(t, string(rows[1].Details), `"failures":1`)
	for _, r := range rows {
		assert.NotContains(t, string(r.Details), created.Record.ID, "no token id in the audit row")
		assert.NotContains(t, string(r.Details), "wrongsecret", "no presented secret in the audit row")
	}
}

func TestTokenLifetimeCapAndDefault(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	ctx := t.Context()
	e.svc.TokenMaxLifetime = 30 * 24 * time.Hour
	now := e.clk.now()

	created, err := e.svc.CreateToken(ctx, e.uid, "defaulted", []string{ScopeRead}, nil, time.Time{})
	require.NoError(t, err)
	assert.True(t, created.Record.ExpiresAt.Equal(now.Add(30*24*time.Hour)), "omitted expiry becomes now plus the maximum")

	_, err = e.svc.CreateToken(ctx, e.uid, "too long", []string{ScopeRead}, nil, now.Add(31*24*time.Hour))
	require.ErrorIs(t, err, ErrTokenLifetime)

	_, err = e.svc.CreateToken(ctx, e.uid, "at the cap", []string{ScopeRead}, nil, now.Add(30*24*time.Hour))
	require.NoError(t, err)

	e.svc.TokenMaxLifetime = 0
	_, err = e.svc.CreateToken(ctx, e.uid, "no limit", []string{ScopeRead}, nil, now.Add(10*365*24*time.Hour))
	require.NoError(t, err, "zero means no limit")
}

func TestTokenCountPerUserIsCapped(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	ctx := t.Context()
	for i := range MaxTokensPerUser {
		_, err := e.svc.CreateToken(ctx, e.uid, "t", []string{ScopeRead}, nil, time.Time{})
		require.NoError(t, err, "token %d", i)
	}
	_, err := e.svc.CreateToken(ctx, e.uid, "one too many", []string{ScopeRead}, nil, time.Time{})
	require.ErrorIs(t, err, ErrTokenLimit)
}

func TestCoalescerWritesOneDueRowPerWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newCoalescer(time.Minute, 10, func() time.Time { return now })
	var rows []int
	for range 3 {
		if n, due := c.note("a"); due {
			rows = append(rows, n)
		}
	}
	now = now.Add(time.Minute)
	if n, due := c.note("a"); due {
		rows = append(rows, n)
	}
	assert.Equal(t, []int{1, 3}, rows)
}
