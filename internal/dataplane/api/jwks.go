package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

const (
	maxJWKSBytes    = 256 << 10
	maxJWKSKeys     = 64
	minRSABits      = 2048
	refetchCooldown = 30 * time.Second
	retryBackoff    = time.Minute
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS decodes a JWK set. Keys it cannot use (encryption keys, unknown
// types, weak RSA) are skipped rather than failing the whole set, so one odd
// entry at the identity provider does not lock every client out.
func ParseJWKS(data []byte) ([]Key, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("JWKS has %d keys, at most %d are accepted", len(set.Keys), maxJWKSKeys)
	}
	var out []Key
	for _, j := range set.Keys {
		if j.Use == "enc" {
			continue
		}
		pub, err := j.public()
		if err != nil {
			continue
		}
		out = append(out, Key{ID: j.Kid, Alg: j.Alg, Public: pub})
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS contains no usable signature key")
	}
	return out, nil
}

func (j jwk) public() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err1 := b64(j.N)
		e, err2 := b64(j.E)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad RSA parameters")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits || pub.E < 3 {
			return nil, errors.New("RSA key too weak")
		}
		return pub, nil
	case "EC":
		var c elliptic.Curve
		switch j.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64(j.X)
		y, err2 := b64(j.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC parameters")
		}
		size := (c.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, errors.New("EC coordinate too long")
		}
		point := make([]byte, 1+2*size) // 0x04 || X || Y, left padded
		point[0] = 4
		copy(point[1+size-len(x):], x)
		copy(point[1+2*size-len(y):], y)
		pub, err := ecdsa.ParseUncompressedPublicKey(c, point) // rejects points that are not on the curve
		if err != nil {
			return nil, fmt.Errorf("EC point: %w", err)
		}
		return pub, nil
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := b64(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("unsupported key type")
}

// ParsePublicKeyPEM reads a PKIX public key (or a certificate) in PEM.
func ParsePublicKeyPEM(s string) (Key, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return Key{}, errors.New("no PEM block")
	}
	var pub any
	if blk.Type == "CERTIFICATE" {
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return Key{}, err
		}
		pub = c.PublicKey
	} else {
		var err error
		if pub, err = x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
			return Key{}, err
		}
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return Key{}, errors.New("RSA key too weak")
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return Key{}, fmt.Errorf("unsupported key type %T", pub)
	}
	return Key{Public: pub}, nil
}

// JWKSSource is a key set kept fresh by a background goroutine. Keys is a lock
// free read of the last good set; a token with an unknown kid asks for an
// early refetch (rate limited) so key rotation is picked up without a request
// ever waiting on the network.
type JWKSSource struct {
	url      string
	refresh  time.Duration
	client   *http.Client
	keys     atomic.Pointer[[]Key]
	wake     chan struct{}
	cancel   context.CancelFunc
	done     chan struct{}
	lastWake atomic.Int64
	refs     int
}

// Keys implements KeySource.
func (s *JWKSSource) Keys(kid string) []Key {
	p := s.keys.Load()
	if p == nil {
		return nil
	}
	got := matchKeys(*p, kid)
	if len(got) == 0 && kid != "" {
		s.requestRefetch()
	}
	return got
}

// Ready reports whether a key set has been fetched.
func (s *JWKSSource) Ready() bool { return s.keys.Load() != nil }

func (s *JWKSSource) requestRefetch() {
	now := time.Now().UnixNano()
	last := s.lastWake.Load()
	if now-last < int64(refetchCooldown) || !s.lastWake.CompareAndSwap(last, now) {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *JWKSSource) run(ctx context.Context) {
	defer close(s.done)
	next := time.Duration(0)
	for {
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
		case <-t.C:
		}
		t.Stop()
		if err := s.fetch(ctx); err != nil {
			slog.Warn("jwks refresh failed; keeping previous keys", "jwks_host", hostOf(s.url), "error", err)
			next = min(retryBackoff, s.refresh)
			continue
		}
		next = s.refresh
	}
}

func (s *JWKSSource) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, err := netx.Get(ctx, s.client, s.url, maxJWKSBytes, http.Header{"Accept": {"application/json"}})
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	s.keys.Store(&keys)
	return nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// JWKSManager shares one background fetcher per URL between every handler
// (and every config reload) that uses it.
type JWKSManager struct {
	mu      sync.Mutex
	sources map[string]*JWKSSource
	// Client fetches key sets. The default refuses private, loopback and
	// link-local addresses (threat T13); tests replace it.
	Client *http.Client
}

// JWKS is the process-wide manager.
var JWKS = &JWKSManager{
	sources: map[string]*JWKSSource{},
	Client:  netx.NewClient(netx.Options{Timeout: 15 * time.Second, MaxRedirects: 2}),
}

// Acquire returns the shared source for url, starting its fetcher on first use.
// Every Acquire needs a matching Release.
func (m *JWKSManager) Acquire(rawURL string, refresh time.Duration) *JWKSSource {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sources[rawURL]; ok {
		s.refs++
		return s
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &JWKSSource{
		url: rawURL, refresh: refresh, client: m.Client, wake: make(chan struct{}, 1),
		cancel: cancel, done: make(chan struct{}), refs: 1,
	}
	m.sources[rawURL] = s
	go s.run(ctx)
	return s
}

// Release drops one reference and stops the fetcher when none are left.
func (m *JWKSManager) Release(rawURL string) {
	m.mu.Lock()
	s, ok := m.sources[rawURL]
	if !ok {
		m.mu.Unlock()
		return
	}
	s.refs--
	if s.refs > 0 {
		m.mu.Unlock()
		return
	}
	delete(m.sources, rawURL)
	m.mu.Unlock()
	s.cancel()
	<-s.done
}
