// Package policy holds request-time primitives shared by data plane modules:
// client IP parsing, CIDR sets and the per-request decision record.
package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ParseIP parses an IP literal as found in headers or socket addresses.
// It tolerates surrounding whitespace, an optional port, IPv6 brackets and
// zone identifiers, and returns the unmapped (IPv4-in-IPv6 collapsed) form.
func ParseIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, fmt.Errorf("parsing ip: empty value")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone("").Unmap(), nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing ip %q: %w", s, err)
	}
	return a.WithZone("").Unmap(), nil
}

// ParseRemoteAddr extracts the IP from an http.Request.RemoteAddr value.
func ParseRemoteAddr(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ParseIP(remote)
	}
	return ParseIP(host)
}

// CIDRSet is an immutable set of prefixes. A bare address is treated as a
// host prefix (/32 or /128). The zero value matches nothing.
type CIDRSet struct {
	prefixes []netip.Prefix
}

// ParseCIDRSet builds a set from CIDR or bare-IP strings.
func ParseCIDRSet(entries []string) (CIDRSet, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for i, e := range entries {
		p, err := parsePrefix(e)
		if err != nil {
			return CIDRSet{}, fmt.Errorf("entry %d: %w", i, err)
		}
		prefixes = append(prefixes, p)
	}
	return CIDRSet{prefixes: prefixes}, nil
}

func parsePrefix(e string) (netip.Prefix, error) {
	e = strings.TrimSpace(e)
	if strings.Contains(e, "/") {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parsing cidr %q: %w", e, err)
		}
		return netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked(), nil
	}
	a, err := ParseIP(e)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmapBits keeps the prefix length meaningful when an IPv4-mapped IPv6
// prefix such as ::ffff:10.0.0.0/104 is collapsed to IPv4.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return max(p.Bits()-96, 0)
	}
	return p.Bits()
}

// Contains reports whether ip is in the set.
func (s CIDRSet) Contains(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the number of prefixes.
func (s CIDRSet) Len() int { return len(s.prefixes) }

// ParsePrefix parses a CIDR or a bare address (a host prefix) into its masked,
// unmapped form. It is the single definition of what an ACL or list entry means.
func ParsePrefix(entry string) (netip.Prefix, error) { return parsePrefix(entry) }
