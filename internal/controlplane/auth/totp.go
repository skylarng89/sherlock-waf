package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; authenticator apps interoperate on HMAC-SHA1
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept the previous and next step for clock drift
)

// NewTOTPSecret returns a 160-bit seed in unpadded base32.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating totp secret: %w", err)
	}
	return base32NoPad.EncodeToString(b), nil
}

// ProvisioningURI is the otpauth:// link authenticator apps import.
func ProvisioningURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step is a positive time counter
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, code)
}

// TOTPStep is the time-step counter for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// MatchTOTP checks code against the seed around now and returns the matching
// step, which the caller must record (store.AdvanceMFAStep) to stop replay.
func MatchTOTP(seed, code string, now time.Time) (step int64, ok bool) {
	secret, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimRight(seed, "=")))
	if err != nil || len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	// Evaluate every candidate without early exit so timing does not reveal which step matched.
	var found int64
	var matched int
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		m := subtle.ConstantTimeCompare([]byte(totpCode(secret, cur+d)), []byte(code))
		if m == 1 {
			found = cur + d
		}
		matched |= m
	}
	return found, matched == 1
}
