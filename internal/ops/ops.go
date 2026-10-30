// Package ops implements the operator commands that work on a node's state
// directly (users, tokens, configuration import/export, audit verification,
// key rotation). The CLI is a thin layer over it, and the tests drive it
// without a process boundary.
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// EnvDatabaseURL selects the database; empty means SQLite in the data dir.
const EnvDatabaseURL = "SHERLOCK_DATABASE_URL"

// Env is an opened node state.
type Env struct {
	Store   store.Store
	Secrets *secrets.Service
	Audit   *audit.Service
	Hasher  *auth.Hasher
	DataDir string
	Logger  *slog.Logger
	// Actor is the operating-system user running the command (see actorID).
	Actor string
}

// OpenOptions locates the node state.
type OpenOptions struct {
	DataDir     string
	DatabaseURL string // overrides SHERLOCK_DATABASE_URL
	Logger      *slog.Logger
}

// DatabaseURL resolves the database location.
func DatabaseURL(dataDir, explicit string) string {
	switch {
	case explicit != "":
		return explicit
	case os.Getenv(EnvDatabaseURL) != "":
		return os.Getenv(EnvDatabaseURL)
	}
	return filepath.Join(dataDir, "sherlock.db")
}

// Open opens the store and loads the node key. The caller closes the store.
func Open(ctx context.Context, o OpenOptions) (*Env, error) {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	st, err := store.Open(ctx, DatabaseURL(o.DataDir, o.DatabaseURL))
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	key, err := secrets.LoadKey(ctx, st, o.DataDir, o.Logger)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("loading node key: %w", err)
	}
	actor := "unknown"
	if u, err := user.Current(); err == nil {
		actor = u.Username
	}
	return &Env{Store: st, Secrets: secrets.New(key), Audit: audit.New(o.Logger), Hasher: auth.NewHasher(2), DataDir: o.DataDir, Logger: o.Logger, Actor: actor}, nil
}

// Close releases the store.
func (e *Env) Close() error { return e.Store.Close() }

// actorID names the operator in the audit log. The table only allows the actor
// types user, token and system, so CLI actions are system actors "cli:<os user>".
func (e *Env) actorID() string { return "cli:" + e.Actor }

func (e *Env) audit(ctx context.Context, tx store.Tx, action, objectType, objectID string, details any) (store.AuditEntry, error) {
	return e.Audit.Append(ctx, tx, audit.Input{ActorType: audit.ActorSystem, ActorID: e.actorID(), Action: action, ObjectType: objectType, ObjectID: objectID, Details: details})
}

// audited runs fn and its audit entry in one transaction.
func (e *Env) audited(ctx context.Context, action, objectType, objectID string, details any, fn func(context.Context, store.Tx) error) error {
	var entry store.AuditEntry
	if err := e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		var err error
		entry, err = e.audit(ctx, tx, action, objectType, objectID, details)
		return err
	}); err != nil {
		return err
	}
	e.Audit.Deliver(ctx, entry)
	return nil
}

func (e *Env) userByName(ctx context.Context, name string) (u store.User, err error) {
	err = e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		u, err = tx.UserByUsername(ctx, name)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return u, fmt.Errorf("no user named %q", name)
	}
	return u, err
}

// CreateUser adds a local account. MFA is enrolled by the user at first sign-in.
func (e *Env) CreateUser(ctx context.Context, username, password, role string) (store.User, error) {
	if role != auth.RoleAdmin && role != auth.RoleViewer {
		return store.User{}, fmt.Errorf("role must be %s or %s", auth.RoleAdmin, auth.RoleViewer)
	}
	if n := len(username); n < 3 || n > 64 || strings.ContainsAny(username, " \t\r\n/:@") {
		return store.User{}, errors.New("username must be 3-64 characters without spaces or any of / : @")
	}
	if err := auth.ValidatePassword(password); err != nil {
		return store.User{}, err
	}
	hash, err := e.Hasher.Hash(ctx, password)
	if err != nil {
		return store.User{}, err
	}
	now := time.Now().UTC()
	id, err := ids.New(now)
	if err != nil {
		return store.User{}, err
	}
	u := store.User{ID: id, Username: username, PasswordHash: hash, Role: role, CreatedAt: now}
	err = e.audited(ctx, "user.create", "user", id, map[string]any{"username": username, "role": role}, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, u)
	})
	if errors.Is(err, store.ErrConflict) {
		return store.User{}, fmt.Errorf("user %q already exists", username)
	}
	return u, err
}

// ResetPassword sets a new password, clears any lock and ends the user's sessions.
func (e *Env) ResetPassword(ctx context.Context, username, password string) error {
	if err := auth.ValidatePassword(password); err != nil {
		return err
	}
	u, err := e.userByName(ctx, username)
	if err != nil {
		return err
	}
	hash, err := e.Hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	return e.audited(ctx, "user.reset_password", "user", u.ID, nil, func(ctx context.Context, tx store.Tx) error {
		if err := tx.SetUserPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		return tx.DeleteUserSessions(ctx, u.ID)
	})
}

// ResetMFA clears the user's TOTP enrolment; they enrol again at next sign-in.
func (e *Env) ResetMFA(ctx context.Context, username string) error {
	u, err := e.userByName(ctx, username)
	if err != nil {
		return err
	}
	return e.audited(ctx, "user.reset_mfa", "user", u.ID, nil, func(ctx context.Context, tx store.Tx) error {
		if err := tx.SetUserMFA(ctx, u.ID, "", false); err != nil {
			return err
		}
		if u.MFASecretID != "" {
			if err := tx.DeleteSecret(ctx, u.MFASecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return tx.DeleteUserSessions(ctx, u.ID)
	})
}

// CreateToken mints an API token for a user.
func (e *Env) CreateToken(ctx context.Context, username, name string, scopes, cidrs []string, expires time.Time) (auth.CreatedToken, error) {
	u, err := e.userByName(ctx, username)
	if err != nil {
		return auth.CreatedToken{}, err
	}
	svc := auth.New(auth.Config{Store: e.Store, Secrets: e.Secrets, Audit: e.Audit, Hasher: e.Hasher, Logger: e.Logger})
	ct, err := svc.CreateToken(ctx, u.ID, name, scopes, cidrs, expires)
	if err != nil {
		return auth.CreatedToken{}, err
	}
	err = e.Audit.Record(ctx, e.Store, audit.Input{
		ActorType: audit.ActorSystem, ActorID: e.actorID(), Action: "token.create", ObjectType: "token", ObjectID: ct.Record.ID,
		Details: map[string]any{"name": name, "scopes": scopes, "user": u.Username},
	})
	return ct, err
}

// ExportConfig returns the live configuration and its version id.
func (e *Env) ExportConfig(ctx context.Context) (*config.Root, string, error) {
	var v store.ConfigVersion
	if err := e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		head, err := tx.ConfigHead(ctx)
		if err != nil {
			return err
		}
		if head == "" {
			return configsvc.ErrNotFound
		}
		v, err = tx.GetConfigVersion(ctx, head)
		return err
	}); err != nil {
		if errors.Is(err, configsvc.ErrNotFound) {
			return nil, "", errors.New("no configuration has been stored yet")
		}
		return nil, "", err
	}
	root, err := config.FromSnapshot(v.Snapshot)
	return root, v.ID, err
}

// ApplyOptions controls ApplyConfig.
type ApplyOptions struct {
	// Source is recorded on the version: configsvc.SourceImport or SourceCLI.
	Source string
	// RequireEmpty refuses to replace an existing configuration.
	RequireEmpty bool
	// Expect, when set, is the version id the replacement is based on.
	Expect string
}

type noActivation struct{}

func (noActivation) Activate(context.Context, *config.Root) error { return nil }

// ApplyConfig stores root as the new head directly in the database. It does not
// touch a running data plane, so the caller must hold the data-dir lock (which a
// running server holds): use the API against a live node.
func (e *Env) ApplyConfig(ctx context.Context, root *config.Root, o ApplyOptions) (store.ConfigVersion, bool, error) {
	svc := configsvc.New(e.Store, e.Audit, noActivation{}, e.Logger)
	svc.SetReferenceChecker(ReferenceChecker(e.Store))
	if err := svc.Boot(ctx); err != nil {
		return store.ConfigVersion{}, false, err
	}
	head := svc.Head()
	if head != "" && o.RequireEmpty {
		return store.ConfigVersion{}, false, errors.New("this node already has a configuration; use `sherlock config apply` to replace it")
	}
	expect := head
	if o.Expect != "" {
		expect = o.Expect
	}
	v, err := svc.Apply(ctx, configsvc.Request{
		Root: root, Expected: expect, Conditional: true, Source: o.Source,
		Actor: configsvc.Actor{Type: audit.ActorSystem, ID: e.actorID()},
	})
	if err != nil {
		return store.ConfigVersion{}, false, err
	}
	return v, v.ID != head, nil
}

// VerifyAudit walks the audit chain.
func (e *Env) VerifyAudit(ctx context.Context) (audit.Report, error) {
	return audit.Verify(ctx, e.Store)
}

// RotateKey re-encrypts every secret under a new node key. A running server
// would keep using the old key, so the caller must hold the data-dir lock.
func (e *Env) RotateKey(ctx context.Context) error {
	_, err := secrets.RotateKey(ctx, e.Store, e.DataDir)
	return err
}

// ReferenceChecker verifies that the certificates and block pages a
// configuration points at exist.
func ReferenceChecker(st store.Store) func(context.Context, *config.Root) config.Errors {
	return func(ctx context.Context, root *config.Root) config.Errors {
		refs := root.References()
		var errs config.Errors
		err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			for id, paths := range refs.Certificates {
				if _, err := tx.GetCertificate(ctx, id); err != nil {
					if !errors.Is(err, store.ErrNotFound) {
						return err
					}
					for _, p := range paths {
						errs = append(errs, config.Error{Path: p, Code: config.CodeNotFound, Message: fmt.Sprintf("certificate %q does not exist", id)})
					}
				}
			}
			for id, paths := range refs.BlockPages {
				if _, err := tx.GetBlockPage(ctx, id); err != nil {
					if !errors.Is(err, store.ErrNotFound) {
						return err
					}
					for _, p := range paths {
						errs = append(errs, config.Error{Path: p, Code: config.CodeNotFound, Message: fmt.Sprintf("block page %q does not exist", id)})
					}
				}
			}
			for id, paths := range refs.OpenAPIDocs {
				if _, err := tx.GetOpenAPIDoc(ctx, id); err != nil {
					if !errors.Is(err, store.ErrNotFound) {
						return err
					}
					for _, p := range paths {
						errs = append(errs, config.Error{Path: p, Code: config.CodeNotFound, Message: fmt.Sprintf("OpenAPI document %q does not exist", id)})
					}
				}
			}
			for id, paths := range refs.CACerts {
				if _, err := tx.GetCABundle(ctx, id); err != nil {
					if !errors.Is(err, store.ErrNotFound) {
						return err
					}
					for _, p := range paths {
						errs = append(errs, config.Error{Path: p, Code: config.CodeNotFound, Message: fmt.Sprintf("CA bundle %q does not exist", id)})
					}
				}
			}
			return nil
		})
		if err != nil { // fail closed: a store error is not "all references exist"
			return config.Errors{{Code: config.CodeInvalid, Message: "could not verify referenced certificates, block pages and API assets: " + err.Error()}}
		}
		slices.SortFunc(errs, func(a, b config.Error) int { return strings.Compare(a.Path, b.Path) })
		return errs
	}
}
