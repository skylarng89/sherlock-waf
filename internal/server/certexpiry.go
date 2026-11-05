package server

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/certstore"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const certExpiryEvery = 60 * time.Second

// certExpiryWatch keeps the expiry of every certificate that serves a site
// host. It refreshes in the background, so a scrape reads a snapshot and never
// touches the disk or the database.
type certExpiryWatch struct {
	cfg     activeConfig
	uploads func(ctx context.Context) (map[string]store.Certificate, error)
	dataDir string
	logger  *slog.Logger
	every   time.Duration

	snap atomic.Pointer[[]metrics.CertExpiry]
}

func newCertExpiryWatch(cfg activeConfig, uploads func(context.Context) (map[string]store.Certificate, error), dataDir string, logger *slog.Logger) *certExpiryWatch {
	return &certExpiryWatch{cfg: cfg, uploads: uploads, dataDir: dataDir, logger: logger, every: certExpiryEvery}
}

// Snapshot returns the last refreshed expiries. It never does I/O.
func (w *certExpiryWatch) Snapshot() []metrics.CertExpiry {
	if s := w.snap.Load(); s != nil {
		return *s
	}
	return nil
}

// Run refreshes until ctx ends.
func (w *certExpiryWatch) Run(ctx context.Context) {
	ticker := time.NewTicker(w.every)
	defer ticker.Stop()
	for {
		w.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *certExpiryWatch) refresh(ctx context.Context) {
	_, root, err := w.cfg.Current(ctx)
	switch {
	case errors.Is(err, configsvc.ErrNotFound):
		w.snap.Store(&[]metrics.CertExpiry{})
		return
	case err != nil:
		w.logger.Warn("certificate expiry refresh skipped: configuration unavailable", "error", err)
		return
	}
	uploaded, err := w.uploads(ctx)
	if err != nil {
		w.logger.Warn("certificate expiry refresh skipped: listing uploaded certificates failed", "error", err)
		return
	}

	var out []metrics.CertExpiry
	for _, s := range root.Sites {
		for _, host := range s.Hosts {
			if notAfter, ok := siteCertExpiry(w.dataDir, uploaded, s.TLS, host); ok {
				out = append(out, metrics.CertExpiry{Site: s.ID, Host: host, NotAfter: notAfter})
			}
		}
	}
	w.snap.Store(&out)
}

// siteCertExpiry resolves the certificate a site host is served with. Hosts
// with no certificate Sherlock can read (none issued yet, or a wildcard ACME
// host, which Caddy stores under a name that is not the host) are omitted.
func siteCertExpiry(dataDir string, uploaded map[string]store.Certificate, tls config.TLS, host string) (time.Time, bool) {
	switch {
	case tls.Mode == config.TLSACME:
		if strings.HasPrefix(host, "*.") {
			return time.Time{}, false
		}
		return certstore.ACMEExpiry(dataDir, host)
	case tls.Mode == config.TLSFile && tls.CertID != "":
		c, ok := uploaded[tls.CertID]
		covered := slices.Contains(c.Hosts, host) || wildcardCovers(c.Hosts, host)
		if !ok || !covered {
			return time.Time{}, false
		}
		return c.NotAfter, true
	}
	return time.Time{}, false
}

// wildcardCovers reports whether a certificate for *.example.test covers
// a.example.test. It matches a single label, as TLS clients do.
func wildcardCovers(names []string, host string) bool {
	_, rest, ok := strings.Cut(host, ".")
	return ok && slices.Contains(names, "*."+rest)
}
