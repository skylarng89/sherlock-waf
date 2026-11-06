package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// MaxFullSessions bounds the concurrent full browser sessions of one user.
// Creating one more evicts the oldest (docs/user/control-plane.md).
const MaxFullSessions = 5

// Self-service errors. The API maps them to 422 field errors; they are not 401,
// because the dashboard treats 401 as an expired session.
var (
	// ErrWrongPassword means the current password did not verify.
	ErrWrongPassword = errors.New("current password is incorrect")
	// ErrSameAsCurrent means the new password equals the current one.
	ErrSameAsCurrent = errors.New("new password must differ from the current password")
	// ErrCurrentSession refuses to revoke the caller's own session; sign-out does that.
	ErrCurrentSession = errors.New("the current session is ended by signing out")
	// ErrMFARequired means the account has two-step verification enrolled and the
	// request carried no verification code.
	ErrMFARequired = errors.New("a verification code is required")
	// ErrPasswordChangedConcurrently means another change committed after this
	// one verified the current password; this change is refused, not applied.
	ErrPasswordChangedConcurrently = errors.New("password changed concurrently")
)

// ChangePassword replaces the caller's password after re-checking the current
// one and, when the account has two-step verification, a current TOTP code (a
// stolen session alone must not be enough to take the account over). Every attempt counts against a per-user limit (the same bound as login)
// but a failure never locks the account. On success every other session of the
// user ends; the caller's session stays signed in.
func (s *Service) ChangePassword(ctx context.Context, p Principal, ip, current, next, totp string) error {
	if p.IsToken() || p.Stage != store.StageFull {
		return ErrUnauthenticated
	}
	if ok, wait := s.passwordLimit.allow(p.UserID); !ok {
		s.auditPasswordChangeFailed(ctx, p.UserID, ip, "throttled")
		return &ThrottledError{RetryAfter: wait}
	}
	u, err := s.userByID(ctx, p.UserID)
	if err != nil {
		return fmt.Errorf("loading user: %w", err)
	}
	if u.LockedUntil.After(s.Now()) {
		s.auditPasswordChangeFailed(ctx, u.ID, ip, "locked")
		return &ThrottledError{RetryAfter: u.LockedUntil.Sub(s.Now())}
	}
	ok, err := s.Hasher.Verify(ctx, current, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("verifying current password: %w", err)
	}
	if !ok {
		s.auditPasswordChangeFailed(ctx, u.ID, ip, "bad_current_password")
		return ErrWrongPassword
	}
	if err := ValidatePassword(next); err != nil {
		s.auditPasswordChangeFailed(ctx, u.ID, ip, "policy")
		return err
	}
	if subtle.ConstantTimeCompare([]byte(current), []byte(next)) == 1 {
		s.auditPasswordChangeFailed(ctx, u.ID, ip, "unchanged")
		return ErrSameAsCurrent
	}
	// The code is checked last among the cheap refusals: checkCode burns the TOTP
	// step, and a policy mistake in the new password must not cost the user a code.
	if u.MFAEnabled {
		if strings.TrimSpace(totp) == "" {
			s.auditPasswordChangeFailed(ctx, u.ID, ip, "mfa_required")
			return ErrMFARequired
		}
		if err := s.checkCode(ctx, u, totp); err != nil {
			if errors.Is(err, ErrInvalidCode) {
				s.auditPasswordChangeFailed(ctx, u.ID, ip, "bad_mfa_code")
			}
			return err
		}
	}
	if s.afterPasswordVerify != nil {
		s.afterPasswordVerify() // test seam: lets a test commit a competing change here
	}
	hash, err := s.Hasher.Hash(ctx, next)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	var entry store.AuditEntry
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		// Compare-and-set on the hash we verified: a concurrent change that won
		// the race must not be silently overwritten (B2).
		changed, err := tx.SetUserPasswordIfCurrent(ctx, u.ID, u.PasswordHash, hash)
		if err != nil {
			return fmt.Errorf("storing password: %w", err)
		}
		if !changed {
			return ErrPasswordChangedConcurrently
		}
		revoked, err := tx.DeleteUserSessionsExcept(ctx, u.ID, p.SessionID)
		if err != nil {
			return fmt.Errorf("ending other sessions: %w", err)
		}
		entry, err = s.Audit.Append(ctx, tx, audit.Input{
			ActorType: audit.ActorUser, ActorID: u.ID, IP: ip, Action: "user.password_changed",
			ObjectType: "user", ObjectID: u.ID,
			// Not "password_*": the audit guard refuses credential-looking keys.
			Details: map[string]any{"self": true, "credentials_changed": true, "sessions_revoked": revoked},
		})
		return err
	}); err != nil {
		if errors.Is(err, ErrPasswordChangedConcurrently) {
			s.auditPasswordChangeFailed(ctx, u.ID, ip, "concurrent_change")
		}
		return err
	}
	s.Audit.Deliver(ctx, entry)
	return nil
}

func (s *Service) auditPasswordChangeFailed(ctx context.Context, userID, ip, reason string) {
	s.audit(ctx, userID, ip, "user.password_change_failed", userID, map[string]any{"reason": reason})
}

// ListSessions returns the caller's full browser sessions, oldest first. Pre-MFA
// sessions are not listed: they are short-lived and not a sign-in the user can act on.
func (s *Service) ListSessions(ctx context.Context, p Principal) ([]store.Session, error) {
	all, err := read(ctx, s.Store, func(ctx context.Context, tx store.Tx) ([]store.Session, error) {
		return tx.ListUserSessions(ctx, p.UserID)
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return slices.DeleteFunc(all, func(sess store.Session) bool { return sess.Stage != store.StageFull }), nil
}

// RevokeSession ends one of the caller's other sessions. An id that belongs to
// another user, or to no session, is store.ErrNotFound, so the response does not
// reveal which ids exist. The caller's own pre-MFA sessions may also be ended
// here; the caller already holds those cookies, so this grants nothing new.
func (s *Service) RevokeSession(ctx context.Context, p Principal, ip, id string) error {
	if id == p.SessionID {
		return ErrCurrentSession
	}
	var deleted bool
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		deleted, err = tx.DeleteUserSessionForUser(ctx, id, p.UserID)
		return err
	}); err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	if !deleted {
		return store.ErrNotFound
	}
	s.audit(ctx, p.UserID, ip, "auth.session_revoked", p.UserID, map[string]any{"self": true})
	return nil
}

// evictOldestFull makes room for one new full session by deleting the user's
// oldest full sessions beyond MaxFullSessions-1. It runs in the transaction that
// creates the session so the count it sees is the count it changes. The audit
// row is appended in the same transaction and delivered by the caller.
func (s *Service) evictOldestFull(ctx context.Context, tx store.Tx, userID string) (*store.AuditEntry, error) {
	// Without the row lock, two concurrent sign-ins on PostgreSQL (READ
	// COMMITTED) both count four sessions and both insert a fifth.
	if _, err := tx.LockUser(ctx, userID); err != nil {
		return nil, fmt.Errorf("locking user for the session cap: %w", err)
	}
	sessions, err := tx.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing sessions for the cap: %w", err)
	}
	full := slices.DeleteFunc(sessions, func(sess store.Session) bool { return sess.Stage != store.StageFull })
	excess := len(full) - (MaxFullSessions - 1)
	if excess <= 0 {
		return nil, nil
	}
	evicted := 0
	for _, sess := range full[:excess] {
		deleted, err := tx.DeleteUserSessionForUser(ctx, sess.ID, userID)
		if err != nil {
			return nil, fmt.Errorf("evicting session: %w", err)
		}
		if deleted {
			evicted++
		}
	}
	e, err := s.Audit.Append(ctx, tx, audit.Input{
		ActorType: audit.ActorUser, ActorID: userID, Action: "auth.session_evicted",
		ObjectType: "user", ObjectID: userID, Details: map[string]any{"evicted": evicted, "cap": MaxFullSessions},
	})
	if err != nil {
		return nil, err
	}
	return &e, nil
}
