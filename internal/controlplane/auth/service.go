package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Session lifetimes (docs/architecture/api.md).
const (
	SessionAbsolute = 12 * time.Hour
	SessionIdle     = 30 * time.Minute
	partialLifetime = 5 * time.Minute
	touchEvery      = time.Minute
	issuer          = "Sherlock WAF"
	mfaPurpose      = "user_mfa_totp"
	tokenPrefix     = "shk"
)

// Errors returned to callers; the API maps them to problem documents.
var (
	// ErrInvalidCredentials covers unknown user, wrong password and disabled
	// account alike so the response never says which.
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidCode        = errors.New("invalid verification code")
	ErrUnauthenticated    = errors.New("not authenticated")
	ErrWrongStage         = errors.New("session is not at this authentication stage")
)

// ThrottledError reports a login refused by rate limiting or a lock.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("too many attempts, retry in %s", e.RetryAfter.Round(time.Second))
}

// Principal is who a request acts as.
type Principal struct {
	UserID      string
	Username    string
	Role        string
	Permissions []string
	Stage       string // store.Stage*; empty for a token
	SessionID   string // hashed id; empty for a token
	TokenID     string // empty for a session
	CSRFHash    string
}

// IsToken reports whether the principal authenticated with an API token.
func (p Principal) IsToken() bool { return p.TokenID != "" }

// Grant is the result of a successful login step: the secrets the client
// keeps. They are shown once and never stored in clear.
type Grant struct {
	SessionToken string
	CSRFToken    string
	Expires      time.Time
	Stage        string
	User         store.User
}

// Config wires the service.
type Config struct {
	Store   store.Store
	Secrets *secrets.Service
	Audit   *audit.Service
	Hasher  *Hasher
	Logger  *slog.Logger
	Now     func() time.Time
}

// Service performs authentication.
type Service struct {
	Config
	ipLimit   *ipLimiter
	nameLimit *ipLimiter
}

// New builds a Service; Logger and Now default sensibly.
func New(c Config) *Service {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Hasher == nil {
		c.Hasher = NewHasher(4)
	}
	return &Service{
		Config: c,
		// 5 attempts/min per IP and per username (docs/architecture/api.md).
		ipLimit:   newIPLimiter(5, time.Minute, c.Now),
		nameLimit: newIPLimiter(5, time.Minute, c.Now),
	}
}

func read[T any](ctx context.Context, st store.Store, fn func(context.Context, store.Tx) (T, error)) (T, error) {
	var out T
	err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = fn(ctx, tx)
		return err
	})
	return out, err
}

func (s *Service) userByID(ctx context.Context, id string) (store.User, error) {
	return read(ctx, s.Store, func(ctx context.Context, tx store.Tx) (store.User, error) { return tx.UserByID(ctx, id) })
}

func (s *Service) audit(ctx context.Context, actorID, ip, action, objectID string, details any) {
	in := audit.Input{ActorType: "user", ActorID: actorID, IP: ip, Action: action, ObjectType: "user", ObjectID: objectID, Details: details}
	if actorID == "" {
		in.ActorType = "anonymous"
	}
	if err := s.Audit.Record(ctx, s.Store, in); err != nil {
		s.Logger.Error("recording audit entry failed", "action", action, "error", err)
	}
}

// Login checks a password. The returned Grant is a partial session when a
// second step is still needed (store.StagePasswordOK or StageMFAEnrolRequire).
func (s *Service) Login(ctx context.Context, ip, userAgent, username, password string) (Grant, error) {
	username = strings.TrimSpace(username)
	if ok, wait := s.ipLimit.allow(ip); !ok {
		s.audit(ctx, "", ip, "auth.login_throttled", "", map[string]any{"scope": "ip"})
		return Grant{}, &ThrottledError{RetryAfter: wait}
	}
	if ok, wait := s.nameLimit.allow(strings.ToLower(username)); !ok {
		s.audit(ctx, "", ip, "auth.login_throttled", "", map[string]any{"scope": "username"})
		return Grant{}, &ThrottledError{RetryAfter: wait}
	}

	u, err := read(ctx, s.Store, func(ctx context.Context, tx store.Tx) (store.User, error) { return tx.UserByUsername(ctx, username) })
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return Grant{}, fmt.Errorf("looking up user: %w", err)
	}
	if errors.Is(err, store.ErrNotFound) || u.Disabled {
		s.Hasher.Dummy(ctx, password)
		s.audit(ctx, "", ip, "auth.login_failed", "", map[string]any{"reason": "unknown_or_disabled"})
		return Grant{}, ErrInvalidCredentials
	}
	now := s.Now()
	if u.LockedUntil.After(now) {
		s.audit(ctx, u.ID, ip, "auth.login_locked", u.ID, nil)
		return Grant{}, &ThrottledError{RetryAfter: u.LockedUntil.Sub(now)}
	}

	ok, err := s.Hasher.Verify(ctx, password, u.PasswordHash)
	if err != nil {
		return Grant{}, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		s.recordFailure(ctx, u, ip, "bad_password")
		return Grant{}, ErrInvalidCredentials
	}

	stage := store.StagePasswordOK
	if !u.MFAEnabled {
		stage = store.StageMFAEnrolRequire
	}
	g, err := s.newSession(ctx, u, stage, ip, userAgent)
	if err != nil {
		return Grant{}, err
	}
	s.audit(ctx, u.ID, ip, "auth.password_ok", u.ID, map[string]any{"stage": stage})
	return g, nil
}

func (s *Service) recordFailure(ctx context.Context, u store.User, ip, reason string) {
	failed := u.FailedCount + 1
	var until time.Time
	if d := lockoutFor(failed); d > 0 {
		until = s.Now().Add(d)
	}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		return tx.RecordLoginFailure(ctx, u.ID, failed, until)
	}); err != nil {
		s.Logger.Error("recording login failure failed", "user_id", u.ID, "error", err)
	}
	s.audit(ctx, u.ID, ip, "auth.login_failed", u.ID, map[string]any{"reason": reason, "failed_count": failed})
}

func (s *Service) newSession(ctx context.Context, u store.User, stage, ip, ua string) (Grant, error) {
	now := s.Now()
	tok, csrf := randomString(32), randomString(32)
	life := SessionAbsolute
	if stage != store.StageFull {
		life = partialLifetime
	}
	rec := store.Session{
		ID: hashToken(tok), UserID: u.ID, Stage: stage, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(life), IP: ip, UserAgent: truncate(ua, 256), CSRFTokenHash: hashToken(csrf),
	}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.CreateSession(ctx, rec) }); err != nil {
		return Grant{}, fmt.Errorf("creating session: %w", err)
	}
	return Grant{SessionToken: tok, CSRFToken: csrf, Expires: rec.ExpiresAt, Stage: stage, User: u}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// VerifyMFA completes a partial session with a TOTP code and returns a new
// full session; the partial one is destroyed so a leaked pre-MFA cookie
// cannot be upgraded.
func (s *Service) VerifyMFA(ctx context.Context, p Principal, ip, userAgent, code string) (Grant, error) {
	if p.Stage != store.StagePasswordOK {
		return Grant{}, ErrWrongStage
	}
	u, err := s.userByID(ctx, p.UserID)
	if err != nil {
		return Grant{}, fmt.Errorf("loading user: %w", err)
	}
	if u.LockedUntil.After(s.Now()) {
		return Grant{}, &ThrottledError{RetryAfter: u.LockedUntil.Sub(s.Now())}
	}
	if err := s.checkCode(ctx, u, code); err != nil {
		if errors.Is(err, ErrInvalidCode) {
			s.recordFailure(ctx, u, ip, "bad_mfa_code")
		}
		return Grant{}, err
	}
	return s.promote(ctx, u, p.SessionID, ip, userAgent)
}

// checkCode validates the code against the stored seed and burns its step.
func (s *Service) checkCode(ctx context.Context, u store.User, code string) error {
	if u.MFASecretID == "" {
		return ErrInvalidCode
	}
	var seed []byte
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		seed, err = s.Secrets.Open(ctx, tx, u.MFASecretID, mfaPurpose)
		return err
	}); err != nil {
		return fmt.Errorf("opening mfa secret: %w", err)
	}
	step, ok := MatchTOTP(string(seed), strings.TrimSpace(code), s.Now())
	if !ok {
		return ErrInvalidCode
	}
	var fresh bool
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		fresh, err = tx.AdvanceMFAStep(ctx, u.ID, step)
		return err
	}); err != nil {
		return fmt.Errorf("recording mfa step: %w", err)
	}
	if !fresh {
		return ErrInvalidCode // replay of a code already used
	}
	return nil
}

func (s *Service) promote(ctx context.Context, u store.User, oldSessionID, ip, ua string) (Grant, error) {
	g, err := s.newSession(ctx, u, store.StageFull, ip, ua)
	if err != nil {
		return Grant{}, err
	}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := tx.DeleteSession(ctx, oldSessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return tx.RecordLoginSuccess(ctx, u.ID, s.Now())
	}); err != nil {
		return Grant{}, fmt.Errorf("completing login: %w", err)
	}
	s.audit(ctx, u.ID, ip, "auth.login", u.ID, nil)
	return g, nil
}

// MFAEnrolment is shown once when a user starts enrolling.
type MFAEnrolment struct{ Secret, URI string }

// StartMFAEnrolment creates a pending TOTP seed for a session that must
// enrol. Calling it again replaces the pending seed.
func (s *Service) StartMFAEnrolment(ctx context.Context, p Principal) (MFAEnrolment, error) {
	if p.Stage != store.StageMFAEnrolRequire {
		return MFAEnrolment{}, ErrWrongStage
	}
	seed, err := NewTOTPSecret()
	if err != nil {
		return MFAEnrolment{}, err
	}
	err = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		u, err := tx.UserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		id, err := s.Secrets.Seal(ctx, tx, mfaPurpose, []byte(seed))
		if err != nil {
			return err
		}
		if err := tx.SetUserMFA(ctx, p.UserID, id, false); err != nil {
			return err
		}
		if u.MFASecretID != "" {
			if err := tx.DeleteSecret(ctx, u.MFASecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return MFAEnrolment{}, fmt.Errorf("starting mfa enrolment: %w", err)
	}
	return MFAEnrolment{Secret: seed, URI: ProvisioningURI(issuer, p.Username, seed)}, nil
}

// ConfirmMFAEnrolment proves the user's authenticator works, enables MFA and
// upgrades the session.
func (s *Service) ConfirmMFAEnrolment(ctx context.Context, p Principal, ip, userAgent, code string) (Grant, error) {
	if p.Stage != store.StageMFAEnrolRequire {
		return Grant{}, ErrWrongStage
	}
	u, err := s.userByID(ctx, p.UserID)
	if err != nil {
		return Grant{}, fmt.Errorf("loading user: %w", err)
	}
	if err := s.checkCode(ctx, u, code); err != nil {
		if errors.Is(err, ErrInvalidCode) {
			s.recordFailure(ctx, u, ip, "bad_mfa_enrol_code")
		}
		return Grant{}, err
	}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := tx.SetUserMFA(ctx, u.ID, u.MFASecretID, true); err != nil {
			return err
		}
		// SetUserMFA resets the replay step; burn this code's step again.
		_, err := tx.AdvanceMFAStep(ctx, u.ID, TOTPStep(s.Now()))
		return err
	}); err != nil {
		return Grant{}, fmt.Errorf("enabling mfa: %w", err)
	}
	s.audit(ctx, u.ID, ip, "auth.mfa_enrolled", u.ID, nil)
	u.MFAEnabled = true
	return s.promote(ctx, u, p.SessionID, ip, userAgent)
}

// Logout ends a session.
func (s *Service) Logout(ctx context.Context, p Principal, ip string) error {
	if p.SessionID == "" {
		return nil
	}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := tx.DeleteSession(ctx, p.SessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	s.audit(ctx, p.UserID, ip, "auth.logout", p.UserID, nil)
	return nil
}

// AuthenticateSession resolves a session cookie value. It enforces absolute
// and idle expiry and that the account is still enabled, and returns
// ErrUnauthenticated for anything else.
func (s *Service) AuthenticateSession(ctx context.Context, cookie string) (Principal, error) {
	if cookie == "" || len(cookie) > 128 {
		return Principal{}, ErrUnauthenticated
	}
	id := hashToken(cookie)
	sess, err := read(ctx, s.Store, func(ctx context.Context, tx store.Tx) (store.Session, error) { return tx.GetSession(ctx, id) })
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, fmt.Errorf("loading session: %w", err)
	}
	now := s.Now()
	if !sess.ExpiresAt.After(now) || now.Sub(sess.LastSeenAt) > SessionIdle {
		return Principal{}, ErrUnauthenticated
	}
	u, err := s.userByID(ctx, sess.UserID)
	if err != nil || u.Disabled {
		return Principal{}, ErrUnauthenticated
	}
	if now.Sub(sess.LastSeenAt) > touchEvery {
		_ = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.TouchSession(ctx, id, now) })
	}
	p := Principal{UserID: u.ID, Username: u.Username, Role: u.Role, Stage: sess.Stage, SessionID: id, CSRFHash: sess.CSRFTokenHash}
	if sess.Stage == store.StageFull {
		p.Permissions = RolePermissions(u.Role)
	}
	return p, nil
}

// CheckCSRF compares the header value with the session's token in constant time.
func CheckCSRF(p Principal, header string) bool {
	if p.CSRFHash == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(header)), []byte(p.CSRFHash)) == 1
}

// CreatedToken is returned once when a token is minted.
type CreatedToken struct {
	Record store.Token
	Secret string // shk_<id>_<secret>
}

// CreateToken mints an API token for userID. Scopes must be valid; CIDRs are
// validated; a zero expires means no expiry.
func (s *Service) CreateToken(ctx context.Context, userID, name string, scopes, cidrs []string, expires time.Time) (CreatedToken, error) {
	if len(scopes) == 0 {
		return CreatedToken{}, errors.New("at least one scope is required")
	}
	for _, sc := range scopes {
		if !ValidScope(sc) {
			return CreatedToken{}, fmt.Errorf("unknown scope %q", sc)
		}
	}
	if _, err := policy.ParseCIDRSet(cidrs); err != nil {
		return CreatedToken{}, fmt.Errorf("cidrs: %w", err)
	}
	now := s.Now()
	if !expires.IsZero() && !expires.After(now) {
		return CreatedToken{}, errors.New("expires_at must be in the future")
	}
	id, err := ids.New(now)
	if err != nil {
		return CreatedToken{}, err
	}
	secret := randomString(32)
	sj, _ := json.Marshal(scopes)
	cj, _ := json.Marshal(append([]string{}, cidrs...))
	rec := store.Token{ID: id, UserID: userID, Name: name, TokenHash: hashToken(secret), Scopes: sj, CIDRs: cj, ExpiresAt: expires, CreatedAt: now}
	if err := s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.CreateToken(ctx, rec) }); err != nil {
		return CreatedToken{}, fmt.Errorf("storing token: %w", err)
	}
	return CreatedToken{Record: rec, Secret: tokenPrefix + "_" + id + "_" + secret}, nil
}

// AuthenticateToken resolves a bearer value of the form shk_<id>_<secret>
// presented from ip.
func (s *Service) AuthenticateToken(ctx context.Context, bearer string, ip netip.Addr) (Principal, error) {
	parts := strings.Split(bearer, "_")
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" || len(bearer) > 200 {
		return Principal{}, ErrUnauthenticated
	}
	rec, err := read(ctx, s.Store, func(ctx context.Context, tx store.Tx) (store.Token, error) { return tx.GetToken(ctx, parts[1]) })
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Burn comparable work so a missing id is not faster than a wrong secret.
			_ = subtle.ConstantTimeCompare([]byte(hashToken(parts[2])), []byte(hashToken("x")))
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, fmt.Errorf("loading token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(parts[2])), []byte(rec.TokenHash)) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	now := s.Now()
	if !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(now) {
		return Principal{}, ErrUnauthenticated
	}
	var cidrs []string
	if err := json.Unmarshal(rec.CIDRs, &cidrs); err != nil {
		return Principal{}, fmt.Errorf("token %s has unreadable cidrs: %w", rec.ID, err)
	}
	set, err := policy.ParseCIDRSet(cidrs)
	if err != nil {
		return Principal{}, fmt.Errorf("token %s has invalid cidrs: %w", rec.ID, err)
	}
	if set.Len() > 0 && !set.Contains(ip) {
		return Principal{}, ErrUnauthenticated
	}
	u, err := s.userByID(ctx, rec.UserID)
	if err != nil || u.Disabled {
		return Principal{}, ErrUnauthenticated
	}
	var scopes []string
	if err := json.Unmarshal(rec.Scopes, &scopes); err != nil {
		return Principal{}, fmt.Errorf("token %s has unreadable scopes: %w", rec.ID, err)
	}
	if now.Sub(rec.LastUsedAt) > touchEvery {
		_ = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.TouchToken(ctx, rec.ID, now) })
	}
	return Principal{UserID: u.ID, Username: u.Username, Role: u.Role, TokenID: rec.ID, Permissions: TokenPermissions(u.Role, scopes)}, nil
}
