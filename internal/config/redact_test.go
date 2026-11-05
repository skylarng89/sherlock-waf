package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatedRoot(hash string) *Root {
	on := true
	gate := &PasswordGate{Enabled: &on, Username: "u", PasswordHash: hash}
	return &Root{
		Global: Global{Defaults: Policy{ACL: &ACLPolicy{PasswordGate: &PasswordGate{Enabled: &on, Username: "d", PasswordHash: hash}}}},
		Sites: []Site{{
			ID: "a", Policy: Policy{ACL: &ACLPolicy{PasswordGate: gate}},
			Endpoints: []Endpoint{{ID: "e", Policy: Policy{ACL: &ACLPolicy{PasswordGate: &PasswordGate{PasswordHash: hash}}}}},
		}},
	}
}

func TestRedactedDoesNotTouchTheOriginal(t *testing.T) {
	r := gatedRoot("$argon2id$secret")
	red := r.Redacted()
	assert.Equal(t, RedactedPlaceholder, red.Sites[0].Policy.ACL.PasswordGate.PasswordHash)
	assert.Equal(t, RedactedPlaceholder, red.Sites[0].Endpoints[0].Policy.ACL.PasswordGate.PasswordHash)
	assert.Equal(t, RedactedPlaceholder, red.Global.Defaults.ACL.PasswordGate.PasswordHash)
	assert.Equal(t, "$argon2id$secret", r.Sites[0].Policy.ACL.PasswordGate.PasswordHash, "the live configuration is shared and must not change")
	assert.Equal(t, "$argon2id$secret", r.Global.Defaults.ACL.PasswordGate.PasswordHash)
}

func TestRestoreRedactedMatchesByIDAndKeepsRealValues(t *testing.T) {
	stored := gatedRoot("$argon2id$secret")
	for name, in := range map[string]string{"placeholder": RedactedPlaceholder, "omitted": ""} {
		next := gatedRoot(in)
		next.RestoreRedacted(stored)
		assert.Equal(t, "$argon2id$secret", next.Sites[0].Policy.ACL.PasswordGate.PasswordHash, name)
		assert.Equal(t, "$argon2id$secret", next.Sites[0].Endpoints[0].Policy.ACL.PasswordGate.PasswordHash, name)
		assert.Equal(t, "$argon2id$secret", next.Global.Defaults.ACL.PasswordGate.PasswordHash, name)
	}

	next := gatedRoot("$argon2id$new")
	next.RestoreRedacted(stored)
	assert.Equal(t, "$argon2id$new", next.Sites[0].Policy.ACL.PasswordGate.PasswordHash, "a supplied hash wins")

	moved := gatedRoot(RedactedPlaceholder)
	moved.Sites[0].ID = "b"
	moved.RestoreRedacted(stored)
	assert.Empty(t, moved.Sites[0].Policy.ACL.PasswordGate.PasswordHash, "a hash never moves to a different site")
	require.Equal(t, "$argon2id$secret", stored.Sites[0].Policy.ACL.PasswordGate.PasswordHash)
}
