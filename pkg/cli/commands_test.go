package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/pkg/cli"
)

const (
	pw     = "correct horse battery"
	sample = `schema_version: 1
global: { admin: { listen: "127.0.0.1:0" } }
sites:
  - id: shop
    hosts: [shop.example.test]
    tls: { mode: none }
    upstreams: { targets: ["127.0.0.1:9"] }
    policy: { mode: block }
`
)

type result struct {
	out, errOut string
	err         error
}

func run(t *testing.T, dir, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := cli.NewRootCommand(cli.BuildInfo{Version: "test"})
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append([]string{"--data-dir", dir}, args...))
	err := cmd.ExecuteContext(context.Background())
	return result{out.String(), errOut.String(), err}
}

func TestUserCommands(t *testing.T) {
	dir := t.TempDir()

	r := run(t, dir, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin")
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, `created admin "ada"`)
	assert.NotContains(t, r.out+r.errOut, pw, "the password is never echoed")

	r = run(t, dir, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin")
	assert.ErrorContains(t, r.err, "already exists")

	r = run(t, dir, "short\n", "user", "create", "bob", "--password-stdin")
	assert.Error(t, r.err, "weak password refused")
	r = run(t, dir, "", "user", "create", "bob", "--password-stdin")
	assert.ErrorContains(t, r.err, "no password on stdin")
	r = run(t, dir, pw+"\n", "user", "create", "bob", "--role", "root", "--password-stdin")
	assert.Error(t, r.err, "unknown role refused")
	r = run(t, dir, "", "user", "create", "bob")
	assert.ErrorContains(t, r.err, "not a terminal", "without --password-stdin and no tty it must not hang or read stdin silently")

	r = run(t, dir, "a different long password\n", "user", "reset-password", "ada", "--password-stdin")
	require.NoError(t, r.err, r.errOut)
	r = run(t, dir, "", "user", "reset-mfa", "ada")
	require.NoError(t, r.err, r.errOut)
	r = run(t, dir, "", "user", "reset-mfa", "ghost")
	assert.ErrorContains(t, r.err, "no user named")

	r = run(t, dir, "", "audit", "verify")
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "audit chain intact: 3 entries")
}

func TestTokenCreatePrintsSecretOnStdoutOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, run(t, dir, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin").err)

	r := run(t, dir, "", "token", "create", "--user", "ada", "--name", "ci", "--scope", "read", "--expires-in", "24h")
	require.NoError(t, r.err, r.errOut)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(r.out), "shk_"), "stdout carries only the token so scripts can capture it")
	assert.Equal(t, 1, strings.Count(strings.TrimSpace(r.out), "\n")+1)
	assert.NotContains(t, r.errOut, "shk_")

	assert.Error(t, run(t, dir, "", "token", "create", "--user", "ada", "--name", "x", "--scope", "root").err)
	assert.Error(t, run(t, dir, "", "token", "create", "--user", "ada", "--name", "x").err, "scope is required")
	assert.Error(t, run(t, dir, "", "token", "create", "--user", "ghost", "--name", "x", "--scope", "read").err)
}

func TestConfigValidateExportImportApply(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "sherlock.yaml")
	require.NoError(t, os.WriteFile(file, []byte(sample), 0o600))

	r := run(t, dir, "", "config", "validate", file)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "valid: 1 site(s)")

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("schema_version: 1\nsites:\n  - id: Bad Id\nbogus: 1\n"), 0o600))
	r = run(t, dir, "", "config", "validate", bad)
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "/bogus", "errors carry JSON pointers")

	r = run(t, dir, "", "config", "export")
	assert.ErrorContains(t, r.err, "no configuration")

	r = run(t, dir, "", "config", "import", file)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "stored version")
	r = run(t, dir, "", "config", "import", file)
	assert.ErrorContains(t, r.err, "already has a configuration")

	r = run(t, dir, "", "config", "apply", file)
	require.NoError(t, r.err)
	assert.Contains(t, r.out, "no change")

	r = run(t, dir, "", "config", "export")
	require.NoError(t, r.err)
	assert.Contains(t, r.out, "id: shop")
	exported := filepath.Join(t.TempDir(), "out.yaml")
	require.NoError(t, run(t, dir, "", "config", "export", "-o", exported).err)

	// The export imports cleanly on a fresh node and exports identically.
	dir2 := t.TempDir()
	require.NoError(t, run(t, dir2, "", "config", "import", exported).err)
	again := run(t, dir2, "", "config", "export")
	require.NoError(t, again.err)
	first := run(t, dir, "", "config", "export")
	assert.Equal(t, first.out, again.out)

	r = run(t, dir, "", "config", "export", "--format", "json")
	require.NoError(t, r.err)
	assert.True(t, strings.HasPrefix(r.out, "{"))
	assert.Error(t, run(t, dir, "", "config", "export", "--format", "toml").err)

	r = run(t, dir, "", "config", "apply", file, "--expect-version", "01STALE")
	assert.Error(t, r.err, "a stale expected version is refused")
}

func TestOfflineConfigRefusesWhileAServerHoldsTheDataDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "sherlock.yaml")
	require.NoError(t, os.WriteFile(file, []byte(sample), 0o600))

	hold := holdLock(t, dir)
	defer hold()
	for _, args := range [][]string{{"config", "import", file}, {"config", "apply", file}, {"secrets", "rotate-key"}} {
		r := run(t, dir, "", args...)
		require.Error(t, r.err, "%v", args)
		assert.Contains(t, r.err.Error(), "--server", "%v: tell the operator how to proceed", args)
	}
	// Reads and user administration remain possible beside a live node.
	require.NoError(t, run(t, dir, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin").err)
}

func TestRemoteFlagsAreValidated(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "sherlock.yaml")
	require.NoError(t, os.WriteFile(file, []byte(sample), 0o600))
	assert.ErrorContains(t, run(t, dir, "", "config", "apply", file, "--server", "http://x").err, "https")
	assert.ErrorContains(t, run(t, dir, "", "config", "apply", file, "--server", "https://127.0.0.1:1").err, "--token")
}

func TestSecretsRotateKeyOffline(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, run(t, dir, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin").err)
	r := run(t, dir, "", "secrets", "rotate-key")
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "rotated")
	require.NoError(t, run(t, dir, "", "audit", "verify").err, "the node still opens after rotation")
}

func TestHashPasswordProducesAVerifiableArgon2idHash(t *testing.T) {
	r := run(t, t.TempDir(), "a gate password\n", "hash-password", "--password-stdin")
	require.NoError(t, r.err, r.errOut)
	hash := strings.TrimSpace(r.out)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$"))
	assert.NotContains(t, r.out+r.errOut, "a gate password")

	// The data-plane gate accepts exactly this format: the config validator takes it.
	_, err := config.Parse([]byte("schema_version: 1\nsites:\n  - id: a\n    hosts: [a.example.test]\n    upstreams: { targets: [\"h:1\"] }\n    policy: { acl: { password_gate: { username: ada, password_hash: \"" + hash + "\" } } }\n"))
	assert.NoError(t, err)

	assert.Error(t, run(t, t.TempDir(), "short\n", "hash-password", "--password-stdin").err, "the password policy applies")
}
