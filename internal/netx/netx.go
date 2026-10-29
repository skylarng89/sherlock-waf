// Package netx builds the HTTP client background jobs use for outbound
// requests to destinations an operator or a feed provider chose. It refuses to
// connect to loopback, private, link-local (including the cloud metadata
// address 169.254.169.254), multicast and unspecified addresses unless the
// caller opts in, and it makes that check on the address actually dialled, so
// DNS rebinding and redirects cannot reach an internal service.
package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned when a connection to a forbidden address is refused.
var ErrBlockedAddress = errors.New("netx: destination address is not allowed")

// Options configures a client.
type Options struct {
	// AllowPrivate permits loopback and private ranges (a CrowdSec API on the
	// same host, for example). Link-local, including the metadata address, stays
	// blocked regardless: no legitimate feed lives there.
	AllowPrivate bool
	Timeout      time.Duration
	MaxRedirects int
}

// Blocked reports whether ip may not be dialled under opts.
func Blocked(ip netip.Addr, allowPrivate bool) bool {
	ip = ip.Unmap()
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return true
	case ip.IsLoopback(), ip.IsPrivate():
		return !allowPrivate
	}
	// 100.64.0.0/10 (carrier-grade NAT) and the IPv6 unique-local/6to4 relay style
	// ranges are internal in practice.
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1]&0xc0 == 64 {
			return !allowPrivate
		}
	}
	return false
}

// NewClient returns an http.Client that enforces the address policy.
func NewClient(o Options) *http.Client {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 3
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		// Control runs after DNS resolution, on the concrete address about to be used.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrBlockedAddress, err)
			}
			if Blocked(ap.Addr(), o.AllowPrivate) {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, ap.Addr())
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			Proxy:                 nil, // never through an environment proxy: it would bypass the address check
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: o.Timeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > o.MaxRedirects {
				return errors.New("netx: too many redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return fmt.Errorf("netx: redirect to %q refused", req.URL.Scheme)
			}
			return nil
		},
	}
}

// Get fetches url with a size limit. A non-200 status is an error.
func Get(ctx context.Context, c *http.Client, rawURL string, maxBytes int64, header http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, fmt.Errorf("netx: scheme %q is not allowed", req.URL.Scheme)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// Query strings and userinfo routinely carry keys; they never reach an error.
	target := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	res, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", target, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", target, err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("fetching %s: response larger than %d bytes", target, maxBytes)
	}
	return b, nil
}
