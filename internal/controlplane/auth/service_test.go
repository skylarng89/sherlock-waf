package auth

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const testPassword = "correct horse battery"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	svc *Service
	st  store.Store
	clk *clock
	uid string
}

func newEnv(t *testing.T, role string) *env {
	t.Helper()
	ctx := t.Context()
	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	dir := t.TempDir()
	key, err := secrets.LoadKey(ctx, st, dir, nil)
	require.NoError(t, err)

	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	h := NewHasher(4)
	hash, err := h.Hash(ctx, testPassword)
	require.NoError(t, err)
	uid := "01USER000000000000000000AA"
	require.NoError(t, st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, store.User{ID: uid, Username: "ada", PasswordHash: hash, Role: role, CreatedAt: clk.now()})
	}))
	svc := New(Config{Store: st, Secrets: secrets.New(key), Audit: audit.New(nil), Hasher: h, Now: clk.now})
	return &env{svc: svc, st: st, clk: clk, uid: uid}
}

func (e *env) code(t *testing.T, seed string, offset int64) string {
	t.Helper()
	raw, err := base32NoPad.DecodeString(seed)
	require.NoError(t, err)
	return totpCode(raw, TOTPStep(e.clk.now())+offset)
}

func (e *env) principal(t *testing.T, g Grant) Principal {
	t.Helper()
	p, err := e.svc.AuthenticateSession(t.Context(), g.SessionToken)
	require.NoError(t, err)
	return p
}

// enrol runs login → enrol → confirm and returns the seed and a full session.
func (e *env) enrol(t *testing.T) (string, Grant) {
	t.Helper()
	ctx := t.Context()
	g, err := e.svc.Login(ctx, "10.0.0.1", "ua", "ada", testPassword)
	require.NoError(t, err)
	require.Equal(t, store.StageMFAEnrolRequire, g.Stage)
	en, err := e.svc.StartMFAEnrolment(ctx, e.principal(t, g))
	require.NoError(t, err)
	full, err := e.svc.ConfirmMFAEnrolment(ctx, e.principal(t, g), "10.0.0.1", "ua", e.code(t, en.Secret, 0))
	require.NoError(t, err)
	require.Equal(t, store.StageFull, full.Stage)
	return en.Secret, full
}

func TestEnrolThenLoginWithMFA(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, full := e.enrol(t)

	p := e.principal(t, full)
	assert.Equal(t, store.StageFull, p.Stage)
	assert.Contains(t, p.Permissions, PermUsersManage)

	// A fresh login now asks for the code instead of enrolment.
	e.clk.advance(2 * time.Minute) // clear the per-IP window and use a new TOTP step
	g, err := e.svc.Login(t.Context(), "10.0.0.1", "ua", "ada", testPassword)
	require.NoError(t, err)
	require.Equal(t, store.StagePasswordOK, g.Stage)
	pp := e.principal(t, g)
	assert.Empty(t, pp.Permissions, "a partial session carries no permissions")

	done, err := e.svc.VerifyMFA(t.Context(), pp, "10.0.0.1", "ua", e.code(t, seed, 0))
	require.NoError(t, err)
	assert.Equal(t, store.StageFull, done.Stage)

	_, err = e.svc.AuthenticateSession(t.Context(), g.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "the pre-MFA cookie must die when the full session is issued")
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, _ := e.enrol(t) // consumed the current step

	e.clk.advance(2 * time.Minute)
	g, err := e.svc.Login(t.Context(), "10.0.0.2", "ua", "ada", testPassword)
	require.NoError(t, err)
	code := e.code(t, seed, 0)
	_, err = e.svc.VerifyMFA(t.Context(), e.principal(t, g), "10.0.0.2", "ua", code)
	require.NoError(t, err)

	g2, err := e.svc.Login(t.Context(), "10.0.0.3", "ua", "ada", testPassword)
	require.NoError(t, err)
	_, err = e.svc.VerifyMFA(t.Context(), e.principal(t, g2), "10.0.0.3", "ua", code)
	assert.ErrorIs(t, err, ErrInvalidCode, "the same code within its window must be refused")
}

func TestWrongStageIsRefused(t *testing.T) {
	e := newEnv(t, RoleViewer)
	g, err := e.svc.Login(t.Context(), "10.0.0.1", "ua", "ada", testPassword)
	require.NoError(t, err)
	p := e.principal(t, g)
	_, err = e.svc.VerifyMFA(t.Context(), p, "ip", "ua", "123456")
	assert.ErrorIs(t, err, ErrWrongStage, "an unenrolled session cannot skip enrolment by verifying")

	_, full := e.enrol(t)
	_, err = e.svc.StartMFAEnrolment(t.Context(), e.principal(t, full))
	assert.ErrorIs(t, err, ErrWrongStage, "a full session cannot re-enrol (that would replace the second factor)")
}

func TestBadCredentialsAreIndistinguishable(t *testing.T) {
	e := newEnv(t, RoleViewer)
	_, err1 := e.svc.Login(t.Context(), "10.0.0.1", "ua", "ada", "wrong password!!")
	_, err2 := e.svc.Login(t.Context(), "10.0.0.2", "ua", "nobody", "wrong password!!")
	assert.ErrorIs(t, err1, ErrInvalidCredentials)
	assert.ErrorIs(t, err2, ErrInvalidCredentials)
	assert.Equal(t, err1.Error(), err2.Error())
}

func TestDisabledUserCannotLogInOrKeepASession(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error { return tx.SetUserDisabled(ctx, e.uid, true) }))

	_, err := e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "disabling an account must end its live sessions")
	e.clk.advance(2 * time.Minute)
	_, err = e.svc.Login(t.Context(), "10.0.0.9", "ua", "ada", testPassword)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAccountLocksWithBackoffAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t, RoleViewer)
	ctx := t.Context()
	// Spread attempts over IPs and time so only the account lock can stop us.
	fail := func(i int) error {
		e.clk.advance(13 * time.Second)
		_, err := e.svc.Login(ctx, "10.1.0."+string(rune('0'+i%10)), "ua", "ada", "wrong password!!")
		return err
	}
	for i := range 4 {
		require.ErrorIs(t, fail(i), ErrInvalidCredentials)
	}
	require.ErrorIs(t, fail(4), ErrInvalidCredentials, "fifth failure sets the first lock")

	var te *ThrottledError
	err := fail(5)
	require.ErrorAs(t, err, &te, "locked account must refuse even before checking the password")
	assert.Positive(t, te.RetryAfter)

	// Correct password during the lock is still refused.
	e.clk.advance(14 * time.Second)
	_, err = e.svc.Login(ctx, "10.9.9.9", "ua", "ada", testPassword)
	require.ErrorAs(t, err, &te)

	e.clk.advance(2 * time.Minute)
	g, err := e.svc.Login(ctx, "10.9.9.8", "ua", "ada", testPassword)
	require.NoError(t, err, "lock expires")
	assert.NotEmpty(t, g.SessionToken)
}

func TestLockoutSchedule(t *testing.T) {
	want := map[int]time.Duration{1: 0, 4: 0, 5: time.Minute, 6: 2 * time.Minute, 7: 4 * time.Minute, 8: 8 * time.Minute, 9: 15 * time.Minute, 50: 15 * time.Minute}
	for n, d := range want {
		assert.Equal(t, d, lockoutFor(n), "failures=%d", n)
	}
}

func TestPerIPThrottle(t *testing.T) {
	e := newEnv(t, RoleViewer)
	for i := range 5 {
		_, err := e.svc.Login(t.Context(), "203.0.113.7", "ua", "user"+string(rune('a'+i)), "x")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	}
	var te *ThrottledError
	_, err := e.svc.Login(t.Context(), "203.0.113.7", "ua", "ada", testPassword)
	require.ErrorAs(t, err, &te, "sixth attempt in a minute from one IP is throttled even with the right password")
	e.clk.advance(61 * time.Second)
	_, err = e.svc.Login(t.Context(), "203.0.113.7", "ua", "ada", testPassword)
	require.NoError(t, err)
}

func TestPerUsernameThrottleCoversUnknownNames(t *testing.T) {
	e := newEnv(t, RoleViewer)
	var te *ThrottledError
	for i := range 6 {
		_, err := e.svc.Login(t.Context(), "198.51.100."+string(rune('1'+i)), "ua", "ghost", "x")
		if i < 5 {
			require.ErrorIs(t, err, ErrInvalidCredentials)
		} else {
			require.ErrorAs(t, err, &te, "unknown usernames are throttled too, so lockout does not reveal which exist")
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)

	e.clk.advance(SessionIdle - time.Minute)
	_, err := e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	require.NoError(t, err, "activity inside the idle window keeps the session")

	e.clk.advance(SessionIdle + time.Minute)
	_, err = e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "idle for longer than 30 minutes")

	_, full = e.enrol2(t)
	for range int(SessionAbsolute / (20 * time.Minute)) {
		e.clk.advance(20 * time.Minute)
		_, _ = e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	}
	e.clk.advance(20 * time.Minute)
	_, err = e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "absolute lifetime is 12h regardless of activity")
}

// enrol2 logs in again for a user who has already enrolled.
func (e *env) enrol2(t *testing.T) (string, Grant) {
	t.Helper()
	var seed string
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		u, err := tx.UserByID(ctx, e.uid)
		if err != nil {
			return err
		}
		b, err := e.svc.Secrets.Open(ctx, tx, u.MFASecretID, mfaPurpose)
		seed = string(b)
		return err
	}))
	e.clk.advance(2 * time.Minute)
	g, err := e.svc.Login(t.Context(), "10.7.7.7", "ua", "ada", testPassword)
	require.NoError(t, err)
	full, err := e.svc.VerifyMFA(t.Context(), e.principal(t, g), "10.7.7.7", "ua", e.code(t, seed, 0))
	require.NoError(t, err)
	return seed, full
}

func TestCSRFCheck(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)
	p := e.principal(t, full)
	assert.True(t, CheckCSRF(p, full.CSRFToken))
	assert.False(t, CheckCSRF(p, ""))
	assert.False(t, CheckCSRF(p, "guess"))
	assert.False(t, CheckCSRF(Principal{}, full.CSRFToken))
}

func TestLogoutEndsSession(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)
	require.NoError(t, e.svc.Logout(t.Context(), e.principal(t, full), "ip"))
	_, err := e.svc.AuthenticateSession(t.Context(), full.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

func TestAuthenticateSessionRejectsGarbage(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	for _, c := range []string{"", "nope", string(make([]byte, 500))} {
		_, err := e.svc.AuthenticateSession(t.Context(), c)
		assert.ErrorIs(t, err, ErrUnauthenticated)
	}
}

func TestTokens(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	ctx := t.Context()
	ip := netip.MustParseAddr("10.0.0.5")

	created, err := e.svc.CreateToken(ctx, e.uid, "ci", []string{ScopeWrite}, []string{"10.0.0.0/24"}, e.clk.now().Add(time.Hour))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		p, err := e.svc.AuthenticateToken(ctx, created.Secret, ip)
		require.NoError(t, err)
		assert.True(t, p.IsToken())
		assert.Equal(t, []string{PermConfigRead, PermConfigWrite, PermSystemRead}, p.Permissions)
		assert.NotContains(t, p.Permissions, PermUsersManage)
	})
	t.Run("stored only as a hash", func(t *testing.T) {
		rec, err := read(ctx, e.st, func(ctx context.Context, tx store.Tx) (store.Token, error) {
			return tx.GetToken(ctx, created.Record.ID)
		})
		require.NoError(t, err)
		assert.NotContains(t, created.Secret, rec.TokenHash)
		assert.Len(t, rec.TokenHash, 64)
		assert.NotContains(t, created.Secret, "=")
	})
	t.Run("wrong secret", func(t *testing.T) {
		_, err := e.svc.AuthenticateToken(ctx, "shk_"+created.Record.ID+"_wrongsecret", ip)
		assert.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("unknown id and malformed", func(t *testing.T) {
		for _, b := range []string{"shk_nope_x", "bad", "shk__x", "shk_a_b_c", "Bearer shk_a_b"} {
			_, err := e.svc.AuthenticateToken(ctx, b, ip)
			assert.ErrorIs(t, err, ErrUnauthenticated, b)
		}
	})
	t.Run("outside cidr", func(t *testing.T) {
		_, err := e.svc.AuthenticateToken(ctx, created.Secret, netip.MustParseAddr("192.0.2.1"))
		assert.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("demoted owner narrows token", func(t *testing.T) {
		require.NoError(t, e.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.SetUserRole(ctx, e.uid, RoleViewer) }))
		p, err := e.svc.AuthenticateToken(ctx, created.Secret, ip)
		require.NoError(t, err)
		assert.NotContains(t, p.Permissions, PermConfigWrite)
		require.NoError(t, e.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.SetUserRole(ctx, e.uid, RoleAdmin) }))
	})
	t.Run("expired", func(t *testing.T) {
		e.clk.advance(2 * time.Hour)
		_, err := e.svc.AuthenticateToken(ctx, created.Secret, ip)
		assert.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("disabled owner", func(t *testing.T) {
		c2, err := e.svc.CreateToken(ctx, e.uid, "x", []string{ScopeRead}, nil, time.Time{})
		require.NoError(t, err)
		_, err = e.svc.AuthenticateToken(ctx, c2.Secret, ip)
		require.NoError(t, err)
		require.NoError(t, e.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.SetUserDisabled(ctx, e.uid, true) }))
		_, err = e.svc.AuthenticateToken(ctx, c2.Secret, ip)
		assert.ErrorIs(t, err, ErrUnauthenticated)
	})
}

func TestCreateTokenValidation(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	ctx := t.Context()
	for name, c := range map[string]struct {
		scopes, cidrs []string
		exp           time.Time
	}{
		"no scopes":   {},
		"bad scope":   {scopes: []string{"root"}},
		"bad cidr":    {scopes: []string{ScopeRead}, cidrs: []string{"nope"}},
		"past expiry": {scopes: []string{ScopeRead}, exp: e.clk.now().Add(-time.Minute)},
	} {
		_, err := e.svc.CreateToken(ctx, e.uid, "n", c.scopes, c.cidrs, c.exp)
		assert.Error(t, err, name)
	}
}

func TestAuditTrailRecordsAuthEventsWithoutCredentials(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, _ := e.enrol(t)
	_, _ = e.svc.Login(t.Context(), "10.5.5.5", "ua", "ada", "wrong password!!")

	var entries []store.AuditEntry
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		entries, err = tx.ListAudit(ctx, 0, 100)
		return err
	}))
	actions := map[string]bool{}
	for _, en := range entries {
		actions[en.Action] = true
		assert.NotContains(t, string(en.Details), testPassword)
		assert.NotContains(t, string(en.Details), seed)
	}
	for _, want := range []string{"auth.password_ok", "auth.mfa_enrolled", "auth.login", "auth.login_failed"} {
		assert.True(t, actions[want], want)
	}
	rep, err := audit.Verify(t.Context(), e.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "audit chain stays valid")
}
