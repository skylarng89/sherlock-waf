package core

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// resolveClientIP implements the rule in request-pipeline.md: when the TCP
// peer is a trusted proxy, take the right-most untrusted address from the
// configured headers (first header that yields one); otherwise use the peer.
// Header values are only ever trusted when they arrive via a trusted proxy.
func resolveClientIP(r *http.Request, trusted policy.CIDRSet, headers []string) (netip.Addr, error) {
	peer, err := policy.ParseRemoteAddr(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !trusted.Contains(peer) {
		return peer, nil
	}
	for _, h := range headers {
		if ip, ok := rightmostUntrusted(r.Header.Values(h), trusted); ok {
			return ip, nil
		}
	}
	return peer, nil
}

func rightmostUntrusted(values []string, trusted policy.CIDRSet) (netip.Addr, bool) {
	var hops []string
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			hops = append(hops, part)
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := policy.ParseIP(hops[i])
		if err != nil {
			// A garbled hop means everything left of it is attacker-controlled
			// or unverifiable; stop rather than skip it.
			return netip.Addr{}, false
		}
		if !trusted.Contains(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
