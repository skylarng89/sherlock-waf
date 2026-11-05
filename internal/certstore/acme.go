package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ACMEExpiry finds the certificate Caddy obtained for host under its storage
// layout (certificates/<issuer>/<host>/<host>.crt) and returns the latest
// NotAfter among the copies found. ok is false when none is readable.
func ACMEExpiry(dataDir, host string) (notAfter time.Time, ok bool) {
	if dataDir == "" || host == "" || strings.ContainsAny(host, `/\`) || strings.HasPrefix(host, ".") {
		return time.Time{}, false
	}
	matches, _ := filepath.Glob(filepath.Join(dataDir, "certificates", "*", host, host+".crt"))
	var best time.Time
	for _, m := range matches {
		raw, err := os.ReadFile(m) //nolint:gosec // path built from the data dir and a validated host name
		if err != nil {
			continue
		}
		blk, _ := pem.Decode(raw)
		if blk == nil {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err == nil && c.NotAfter.After(best) {
			best = c.NotAfter
		}
	}
	return best, !best.IsZero()
}
