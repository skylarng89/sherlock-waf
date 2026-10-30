package ops

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const pw = "correct horse battery"

func open(t *testing.T) *Env {
	t.Helper()
	e, err := Open(t.Context(), OpenOptions{DataDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

const sample = `
schema_version: 1
global: { admin: { listen: "127.0.0.1:0" } }
sites:
  - id: shop
    hosts: [shop.example.test]
    tls: { mode: none }
    upstreams: { targets: ["127.0.0.1:9"] }
    policy: { mode: block, waf: { paranoia_level: 2 } }
    endpoints:
      - { id: login, match: { path: /login, methods: [POST] }, policy: { waf: { paranoia_level: 3 } } }
`

func TestFreshNodeHasNoUsers(t *testing.T) {
	e := open(t)
	var n int
	require.NoError(t, e.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		n, err = tx.CountUsers(ctx)
		return err
	}))
	assert.Zero(t, n, "AC1: no default account exists on a fresh node")
}

func TestCreateUserValidatesAndAudits(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	for name, c := range map[string]struct{ user, pass, role string }{
		"bad role":      {"ada", pw, "root"},
		"short name":    {"ad", pw, "admin"},
		"spaced name":   {"a da", pw, "admin"},
		"weak password": {"ada", "short", "admin"},
	} {
		_, err := e.CreateUser(ctx, c.user, c.pass, c.role)
		assert.Error(t, err, name)
	}
	u, err := e.CreateUser(ctx, "ada", pw, "admin")
	require.NoError(t, err)
	assert.NotEqual(t, pw, u.PasswordHash)
	_, err = e.CreateUser(ctx, "ada", pw, "admin")
	assert.ErrorContains(t, err, "already exists")

	rep, err := e.VerifyAudit(ctx)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem)
	assert.Equal(t, 1, rep.Entries, "only the successful creation is audited")
}

func TestResetPasswordUnlocksAndRevokesSessions(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	u, err := e.CreateUser(ctx, "ada", pw, "admin")
	require.NoError(t, err)
	require.NoError(t, e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := tx.RecordLoginFailure(ctx, u.ID, 9, time.Now().Add(time.Hour)); err != nil {
			return err
		}
		return tx.CreateSession(ctx, store.Session{ID: "s1", UserID: u.ID, Stage: store.StageFull, CreatedAt: time.Now(), LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}))

	require.Error(t, e.ResetPassword(ctx, "ada", "short"))
	require.Error(t, e.ResetPassword(ctx, "nobody", pw))
	require.NoError(t, e.ResetPassword(ctx, "ada", "another long password"))

	require.NoError(t, e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		got, err := tx.UserByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.LockedUntil.IsZero(), "reset clears the lock")
		assert.Zero(t, got.FailedCount)
		_, err = tx.GetSession(ctx, "s1")
		assert.ErrorIs(t, err, store.ErrNotFound, "existing sessions end")
		ok, err := e.Hasher.Verify(ctx, "another long password", got.PasswordHash)
		require.NoError(t, err)
		assert.True(t, ok)
		return nil
	}))
}

func TestResetMFA(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	u, err := e.CreateUser(ctx, "ada", pw, "admin")
	require.NoError(t, err)
	var secretID string
	require.NoError(t, e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		if secretID, err = e.Secrets.Seal(ctx, tx, "user_mfa_totp", []byte("SEED")); err != nil {
			return err
		}
		return tx.SetUserMFA(ctx, u.ID, secretID, true)
	}))
	require.NoError(t, e.ResetMFA(ctx, "ada"))
	require.NoError(t, e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		got, err := tx.UserByID(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.MFAEnabled)
		assert.Empty(t, got.MFASecretID)
		_, err = tx.GetSecret(ctx, secretID)
		assert.ErrorIs(t, err, store.ErrNotFound, "the seed is deleted, not just unlinked")
		return nil
	}))
}

func TestCreateTokenWorksWithTheAuthService(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	_, err := e.CreateUser(ctx, "ada", pw, "admin")
	require.NoError(t, err)
	_, err = e.CreateToken(ctx, "nobody", "ci", []string{"read"}, nil, time.Time{})
	require.Error(t, err)
	_, err = e.CreateToken(ctx, "ada", "ci", []string{"root"}, nil, time.Time{})
	require.Error(t, err)

	ct, err := e.CreateToken(ctx, "ada", "ci", []string{"write"}, nil, time.Time{})
	require.NoError(t, err)
	svc := auth.New(auth.Config{Store: e.Store, Secrets: e.Secrets, Audit: e.Audit})
	p, err := svc.AuthenticateToken(ctx, ct.Secret, netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	assert.Contains(t, p.Permissions, auth.PermConfigWrite)
}

func TestExportImportReproducesTheCompiledConfig(t *testing.T) {
	src := open(t)
	ctx := t.Context()
	root, err := config.Parse([]byte(sample))
	require.NoError(t, err)

	_, _, err = src.ExportConfig(ctx)
	require.ErrorContains(t, err, "no configuration", "export before any import says so")

	v, changed, err := src.ApplyConfig(ctx, root, ApplyOptions{Source: configsvc.SourceImport, RequireEmpty: true})
	require.NoError(t, err)
	assert.True(t, changed)

	exported, id, err := src.ExportConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, v.ID, id)
	yml, err := config.MarshalYAML(exported)
	require.NoError(t, err)

	// A fresh node imports the exported YAML.
	dst := open(t)
	parsed, err := config.Parse(yml)
	require.NoError(t, err, string(yml))
	_, _, err = dst.ApplyConfig(ctx, parsed, ApplyOptions{Source: configsvc.SourceImport, RequireEmpty: true})
	require.NoError(t, err)
	got, _, err := dst.ExportConfig(ctx)
	require.NoError(t, err)

	opts := compiler.Options{HTTPPort: 8080, HTTPSPort: 8443, DataDir: "/data"}
	want, err := compiler.Compile(root, opts)
	require.NoError(t, err)
	have, err := compiler.Compile(got, opts)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(have), "AC9: identical compiled Caddy JSON")
}

func TestApplyConfigGuards(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	root, err := config.Parse([]byte(sample))
	require.NoError(t, err)
	first, _, err := e.ApplyConfig(ctx, root, ApplyOptions{Source: configsvc.SourceImport, RequireEmpty: true})
	require.NoError(t, err)

	_, _, err = e.ApplyConfig(ctx, root, ApplyOptions{Source: configsvc.SourceImport, RequireEmpty: true})
	assert.ErrorContains(t, err, "already has a configuration", "import refuses to overwrite")

	again, changed, err := e.ApplyConfig(ctx, root, ApplyOptions{Source: configsvc.SourceCLI})
	require.NoError(t, err)
	assert.False(t, changed, "applying an identical file is a no-op")
	assert.Equal(t, first.ID, again.ID)

	_, _, err = e.ApplyConfig(ctx, root, ApplyOptions{Source: configsvc.SourceCLI, Expect: "01STALE"})
	assert.ErrorIs(t, err, configsvc.ErrPreconditionFailed)

	bad := *root
	bad.Sites = append([]config.Site{}, root.Sites...)
	bad.Sites[0].ID = "Bad Id"
	_, _, err = e.ApplyConfig(ctx, &bad, ApplyOptions{Source: configsvc.SourceCLI})
	var inv *configsvc.InvalidError
	assert.ErrorAs(t, err, &inv)
}

func TestDataDirLockExcludesASecondHolder(t *testing.T) {
	dir := t.TempDir()
	release, err := Lock(dir)
	require.NoError(t, err)
	_, err = Lock(dir)
	require.ErrorIs(t, err, ErrLocked)
	release()
	release2, err := Lock(dir)
	require.NoError(t, err, "released lock can be taken again")
	release2()
}

func TestRotateKeyKeepsSecretsReadable(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	var id string
	require.NoError(t, e.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		id, err = e.Secrets.Seal(ctx, tx, "user_mfa_totp", []byte("SEED"))
		return err
	}))
	require.NoError(t, e.RotateKey(ctx))
	require.NoError(t, e.Close())

	e2, err := Open(ctx, OpenOptions{DataDir: e.DataDir})
	require.NoError(t, err)
	defer e2.Close()
	require.NoError(t, e2.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		pt, err := e2.Secrets.Open(ctx, tx, id, "user_mfa_totp")
		require.NoError(t, err)
		assert.Equal(t, "SEED", string(pt))
		return nil
	}))
}
