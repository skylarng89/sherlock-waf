package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

const updated = "a fresh passphrase here"

func addUser(t *testing.T, e *env, id, name string) {
	t.Helper()
	hash, err := e.svc.Hasher.Hash(t.Context(), testPassword)
	require.NoError(t, err)
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, store.User{ID: id, Username: name, PasswordHash: hash, Role: RoleViewer, CreatedAt: e.clk.now()})
	}))
}

// fullSession signs in from a fresh address and completes MFA. It moves the clock
// past the per-IP window and the next TOTP step first.
func (e *env) fullSession(t *testing.T, seed, ip string) Grant {
	t.Helper()
	e.clk.advance(2 * time.Minute)
	g, err := e.svc.Login(t.Context(), ip, "ua", "ada", testPassword)
	require.NoError(t, err)
	full, err := e.svc.VerifyMFA(t.Context(), e.principal(t, g), ip, "ua", e.code(t, seed, 0))
	require.NoError(t, err)
	require.Equal(t, store.StageFull, full.Stage)
	return full
}

// freshCode moves the clock one minute on and returns the current code, so the
// TOTP step differs from every step already burned in the test.
func (e *env) freshCode(t *testing.T, seed string) string {
	t.Helper()
	e.clk.advance(time.Minute)
	return e.code(t, seed, 0)
}

func TestChangePasswordEndsOtherSessionsAndKeepsCaller(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, first := e.enrol(t)
	other := e.fullSession(t, seed, "10.0.2.1")
	caller := e.principal(t, first)

	require.NoError(t, e.svc.ChangePassword(t.Context(), caller, "10.0.0.1", testPassword, updated, e.freshCode(t, seed)))

	_, err := e.svc.AuthenticateSession(t.Context(), other.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "other sessions end")
	_, err = e.svc.AuthenticateSession(t.Context(), first.SessionToken)
	require.NoError(t, err, "the caller stays signed in")

	e.clk.advance(2 * time.Minute)
	_, err = e.svc.Login(t.Context(), "10.0.3.1", "ua", "ada", testPassword)
	assert.ErrorIs(t, err, ErrInvalidCredentials, "the old password stops working")
	_, err = e.svc.Login(t.Context(), "10.0.3.2", "ua", "ada", updated)
	require.NoError(t, err, "the new password works")
}

func TestChangePasswordRefusals(t *testing.T) {
	cases := []struct {
		name    string
		current string
		next    string
		want    error
	}{
		{"unchanged", testPassword, testPassword, ErrSameAsCurrent},
		{"too short", testPassword, "short", ErrWeakPassword},
		{"common", testPassword, "password1234", ErrWeakPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, RoleAdmin)
			_, full := e.enrol(t)
			err := e.svc.ChangePassword(t.Context(), e.principal(t, full), "10.0.0.1", tc.current, tc.next, "")
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestWrongCurrentPasswordIsThrottledWithoutLockingTheAccount(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)
	p := e.principal(t, full)

	for range 5 {
		err := e.svc.ChangePassword(t.Context(), p, "10.0.0.1", "wrong guess", updated, "")
		require.ErrorIs(t, err, ErrWrongPassword)
	}
	var throttled *ThrottledError
	err := e.svc.ChangePassword(t.Context(), p, "10.0.0.1", testPassword, updated, "")
	assert.True(t, errors.As(err, &throttled), "the sixth attempt is refused even with the right password")

	u, err := read(t.Context(), e.st, func(ctx context.Context, tx store.Tx) (store.User, error) { return tx.UserByUsername(ctx, "ada") })
	require.NoError(t, err)
	assert.True(t, u.LockedUntil.IsZero(), "a failed change must not lock the account")

	e.clk.advance(2 * time.Minute)
	_, err = e.svc.Login(t.Context(), "10.0.0.9", "ua", "ada", testPassword)
	require.NoError(t, err, "login is not blocked by the change-password limit")
}

func TestTokensAndPartialSessionsCannotChangePasswordOrListSessions(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, full := e.enrol(t)
	ctx := t.Context()
	partial := Principal{UserID: e.uid, Username: "ada", Role: RoleAdmin, Stage: store.StagePasswordOK, SessionID: "partial"}
	tokenPrincipal := Principal{UserID: e.uid, Username: "ada", Role: RoleAdmin, TokenID: "01TOKEN"}

	for _, p := range []Principal{partial, tokenPrincipal} {
		err := e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, updated, "")
		assert.ErrorIs(t, err, ErrUnauthenticated)
	}
	require.NoError(t, e.svc.ChangePassword(ctx, e.principal(t, full), "10.0.0.1", testPassword, updated, e.freshCode(t, seed)), "a full session can")
}

func TestRevokeSessionIsScopedToTheCaller(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, first := e.enrol(t)
	mine := e.fullSession(t, seed, "10.0.2.1")
	const bobID = "01BOB0000000000000000000BB"
	addUser(t, e, bobID, "bob")
	e.clk.advance(2 * time.Minute)
	bobGrant, err := e.svc.Login(t.Context(), "10.0.5.1", "ua", "bob", testPassword)
	require.NoError(t, err)
	bob := e.principal(t, bobGrant)

	caller := e.principal(t, first)
	assert.ErrorIs(t, e.svc.RevokeSession(t.Context(), caller, "10.0.0.1", caller.SessionID), ErrCurrentSession,
		"revoking the caller's own session is refused: sign-out does that")

	err = e.svc.RevokeSession(t.Context(), bob, "10.0.0.7", e.principal(t, mine).SessionID)
	assert.ErrorIs(t, err, store.ErrNotFound, "another user's session looks like no session")
	_, err = e.svc.AuthenticateSession(t.Context(), mine.SessionToken)
	require.NoError(t, err, "the victim's session survives a foreign revoke")

	require.NoError(t, e.svc.RevokeSession(t.Context(), caller, "10.0.0.1", e.principal(t, mine).SessionID))
	_, err = e.svc.AuthenticateSession(t.Context(), mine.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "the caller's own other session ends")

	err = e.svc.RevokeSession(t.Context(), caller, "10.0.0.1", "no-such-id")
	assert.ErrorIs(t, err, store.ErrNotFound)
	_, err = e.svc.AuthenticateSession(t.Context(), first.SessionToken)
	require.NoError(t, err)
}

func TestListSessionsShowsOnlyFullSessionsOfTheCaller(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, first := e.enrol(t)
	e.fullSession(t, seed, "10.0.2.1")
	e.clk.advance(2 * time.Minute)
	_, err := e.svc.Login(t.Context(), "10.0.2.2", "ua", "ada", testPassword) // leaves a partial session
	require.NoError(t, err)

	got, err := e.svc.ListSessions(t.Context(), e.principal(t, first))
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, s := range got {
		assert.Equal(t, store.StageFull, s.Stage)
		assert.Equal(t, e.uid, s.UserID)
	}
}

// The cap is enforced where sessions are created, so the sixth full session
// pushes out the oldest one and nothing else.
func TestSessionCapEvictsTheOldestFullSession(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, first := e.enrol(t)
	sessions := []Grant{first}
	for i := range MaxFullSessions {
		sessions = append(sessions, e.fullSession(t, seed, "10.0.4."+string(rune('1'+i))))
	}
	require.Len(t, sessions, MaxFullSessions+1)

	_, err := e.svc.AuthenticateSession(t.Context(), first.SessionToken)
	assert.ErrorIs(t, err, ErrUnauthenticated, "the oldest session is evicted")
	for _, g := range sessions[1:] {
		_, err := e.svc.AuthenticateSession(t.Context(), g.SessionToken)
		require.NoError(t, err)
	}
	got, err := e.svc.ListSessions(t.Context(), e.principal(t, sessions[len(sessions)-1]))
	require.NoError(t, err)
	assert.Len(t, got, MaxFullSessions)
}

func TestConcurrentPasswordChangeLosesCompareAndSet(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, _ := e.enrol(t)
	g := e.fullSession(t, seed, "10.7.0.1")
	p := e.principal(t, g)
	ctx := t.Context()

	const first, second = "second correct horse 1", "third correct horse 2"
	loserCode := e.freshCode(t, seed)
	winnerCode := e.code(t, seed, 1) // the next step: valid within the skew window and not yet used
	winner := func() {
		e.svc.afterPasswordVerify = nil // the competing change must not re-enter the hook
		require.NoError(t, e.svc.ChangePassword(ctx, p, "10.7.0.1", testPassword, first, winnerCode))
	}
	// The stale change verifies the old password, then a competing change commits
	// before it writes. Its write must be refused, not applied over the winner.
	e.svc.afterPasswordVerify = winner
	err := e.svc.ChangePassword(ctx, p, "10.7.0.1", testPassword, second, loserCode)
	require.ErrorIs(t, err, ErrPasswordChangedConcurrently)

	u, err := read(ctx, e.st, func(ctx context.Context, tx store.Tx) (store.User, error) { return tx.UserByID(ctx, e.uid) })
	require.NoError(t, err)
	ok, err := e.svc.Hasher.Verify(ctx, first, u.PasswordHash)
	require.NoError(t, err)
	assert.True(t, ok, "the winner's password stands")
	ok, _ = e.svc.Hasher.Verify(ctx, second, u.PasswordHash)
	assert.False(t, ok, "the loser's password was never stored")
	assert.Len(t, auditRows(t, e.st, "user.password_change_failed"), 1, "the refused change is audited without its passwords")
}

func TestChangePasswordRequiresAFreshCodeWhenMFAIsEnrolled(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	seed, full := e.enrol(t)
	p := e.principal(t, full)
	ctx := t.Context()

	err := e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, updated, "")
	assert.ErrorIs(t, err, ErrMFARequired, "a session cookie and the password are not enough")

	err = e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, updated, "000000")
	assert.ErrorIs(t, err, ErrInvalidCode, "a wrong code is refused")

	// The code that completed enrolment is already burned: replay is refused.
	err = e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, updated, e.code(t, seed, 0))
	assert.ErrorIs(t, err, ErrInvalidCode, "a replayed code is refused")

	// A policy mistake must not burn the code the user just typed.
	code := e.freshCode(t, seed)
	err = e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, "short", code)
	assert.ErrorIs(t, err, ErrWeakPassword)
	require.NoError(t, e.svc.ChangePassword(ctx, p, "10.0.0.1", testPassword, updated, code), "the same code still works after a policy refusal")

	_, err = e.svc.Login(ctx, "10.9.0.1", "ua", "ada", testPassword)
	assert.ErrorIs(t, err, ErrInvalidCredentials, "only the successful change took effect")
	reasons := ""
	for _, r := range auditRows(t, e.st, "user.password_change_failed") {
		reasons += string(r.Details)
	}
	for _, want := range []string{"mfa_required", "bad_mfa_code"} {
		assert.Contains(t, reasons, want)
	}
	assert.NotContains(t, reasons, "000000", "codes never reach the audit log")
}

func TestChangePasswordIgnoresACodeWithoutMFA(t *testing.T) {
	e := newEnv(t, RoleAdmin)
	_, full := e.enrol(t)
	ctx := t.Context()
	require.NoError(t, e.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		return tx.SetUserMFA(ctx, e.uid, "", false)
	}))
	require.NoError(t, e.svc.ChangePassword(ctx, e.principal(t, full), "10.0.0.1", testPassword, updated, ""),
		"an account without two-step verification needs no code")
}
