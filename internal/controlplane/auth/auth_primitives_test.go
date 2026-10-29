package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordRoundTrip(t *testing.T) {
	h := NewHasher(2)
	hash, err := h.Hash(t.Context(), "correct horse battery")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$"))

	ok, err := h.Verify(t.Context(), "correct horse battery", hash)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = h.Verify(t.Context(), "correct horse batterY", hash)
	require.NoError(t, err)
	assert.False(t, ok)

	other, err := h.Hash(t.Context(), "correct horse battery")
	require.NoError(t, err)
	assert.NotEqual(t, hash, other, "salt must differ per hash")
}

func TestVerifyRejectsMalformedAndAbusiveHashes(t *testing.T) {
	h := NewHasher(1)
	for name, enc := range map[string]string{
		"empty":      "",
		"bcrypt":     "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"argon2i":    "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"huge-mem":   "$argon2id$v=19$m=4194304,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"huge-time":  "$argon2id$v=19$m=65536,t=4000,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"zero-lanes": "$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"short-salt": "$argon2id$v=19$m=65536,t=3,p=2$YQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"bad-b64":    "$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
	} {
		ok, err := h.Verify(t.Context(), "x", enc)
		assert.False(t, ok, name)
		assert.Error(t, err, name)
	}
}

func TestHasherBoundsConcurrencyAndHonoursContext(t *testing.T) {
	h := NewHasher(1)
	release, err := h.acquire(t.Context())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = h.Hash(ctx, "whatever password")
	require.ErrorIs(t, err, context.DeadlineExceeded, "a full semaphore must not block past the context")
}

func TestValidatePassword(t *testing.T) {
	require.NoError(t, ValidatePassword("twelve chars!"))
	for _, p := range []string{"", "short", "           ", strings.Repeat("a", 1025)} {
		require.ErrorIs(t, ValidatePassword(p), ErrWeakPassword, "%q", p)
	}
}

// RFC 6238 appendix B, SHA-1, 8 digits truncated to our 6.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		assert.Equal(t, want, totpCode(secret, ts/30), "t=%d", ts)
	}
}

func TestMatchTOTPSkewAndReplayStep(t *testing.T) {
	seed, err := NewTOTPSecret()
	require.NoError(t, err)
	secret, err := base32NoPad.DecodeString(seed)
	require.NoError(t, err)

	now := time.Unix(1_800_000_000, 0)
	cur := TOTPStep(now)
	for d, wantOK := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		step, ok := MatchTOTP(seed, totpCode(secret, cur+d), now)
		assert.Equal(t, wantOK, ok, "offset %d", d)
		if ok {
			assert.Equal(t, cur+d, step, "caller needs the matched step for replay protection")
		}
	}
	_, ok := MatchTOTP(seed, "12345", now)
	assert.False(t, ok)
	_, ok = MatchTOTP(seed, "abcdef", now)
	assert.False(t, ok)
	_, ok = MatchTOTP("not base32 !!", "123456", now)
	assert.False(t, ok)
}

func TestProvisioningURI(t *testing.T) {
	u := ProvisioningURI("Sherlock WAF", "ada", "JBSWY3DPEHPK3PXP")
	assert.Equal(t, "otpauth://totp/Sherlock%20WAF:ada?algorithm=SHA1&digits=6&issuer=Sherlock+WAF&period=30&secret=JBSWY3DPEHPK3PXP", u)
}

func TestTokenPermissionsAreBoundedByRole(t *testing.T) {
	assert.Equal(t, []string{PermConfigRead, PermConfigWrite, PermSystemRead}, TokenPermissions(RoleAdmin, []string{ScopeWrite}))
	assert.Equal(t, []string{PermConfigRead, PermEventsRead, PermSystemRead}, TokenPermissions(RoleViewer, []string{ScopeWrite, ScopeAdmin}),
		"a demoted user's admin-scope token must not gain write")
	assert.NotContains(t, TokenPermissions(RoleAdmin, []string{ScopeAdmin}), PermTokensOwn, "tokens cannot mint tokens")
	assert.Empty(t, TokenPermissions("ghost", []string{ScopeAdmin}))
	assert.Empty(t, RolePermissions("ghost"))
}

func TestRandomStringShapeAndHash(t *testing.T) {
	a, b := randomString(32), randomString(32)
	assert.NotEqual(t, a, b)
	assert.NotContains(t, a, "_")
	assert.Equal(t, a, strings.ToLower(a))
	assert.Len(t, hashToken(a), 64)
	assert.NotEqual(t, hashToken(a), hashToken(b))
}

func TestValidatePasswordRejectsPredictable(t *testing.T) {
	for _, bad := range []string{"password1234", "PASSWORD1234", "aaaaaaaaaaaa", "123456789012", "abcdefghijkl", "short", "            "} {
		assert.ErrorIs(t, ValidatePassword(bad), ErrWeakPassword, bad)
	}
	for _, good := range []string{"correct horse battery", "tr0ub4dor&3-staple", "a1b2c3d4e5f6g7"} {
		assert.NoError(t, ValidatePassword(good), good)
	}
}
