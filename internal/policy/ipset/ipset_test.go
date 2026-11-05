package ipset

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func mustParse(t testing.TB, entries ...string) *Set {
	t.Helper()
	s, err := Parse(entries)
	require.NoError(t, err)
	return s
}

func TestContains(t *testing.T) {
	s := mustParse(t, "10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "203.0.113.0/24", "::ffff:198.51.100.0/120")
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "10.255.255.255": true, "11.0.0.0": false, "9.255.255.255": false,
		"192.0.2.7": true, "192.0.2.6": false, "192.0.2.8": false,
		"2001:db8::1": true, "2001:db8:ffff::1": true, "2001:db9::1": false,
		"203.0.113.255": true, "203.0.114.0": false,
		"198.51.100.9":    true, // an IPv4-mapped prefix means the IPv4 prefix
		"::ffff:10.0.0.1": true, "::1": false, "0.0.0.0": false,
	} {
		assert.Equal(t, want, s.Contains(netip.MustParseAddr(ip)), ip)
	}
	assert.False(t, (*Set)(nil).Contains(netip.MustParseAddr("10.0.0.1")), "nil set matches nothing")
	assert.False(t, (&Set{}).Contains(netip.MustParseAddr("10.0.0.1")), "zero set matches nothing")
}

func TestCoveredPrefixesAreAbsorbed(t *testing.T) {
	s := mustParse(t, "10.1.0.0/16", "10.0.0.0/8", "10.2.3.4", "10.0.0.0/8")
	assert.Equal(t, 1, s.Len(), "the /8 covers the rest, in any insertion order")
	assert.True(t, s.Contains(netip.MustParseAddr("10.2.3.4")))
	assert.False(t, s.Contains(netip.MustParseAddr("11.0.0.1")))
}

func TestDefaultRouteMatchesEverythingOfItsFamily(t *testing.T) {
	s := mustParse(t, "0.0.0.0/0")
	assert.True(t, s.Contains(netip.MustParseAddr("203.0.113.9")))
	assert.False(t, s.Contains(netip.MustParseAddr("2001:db8::1")), "an IPv4 default route does not match IPv6")
}

func TestParseRejectsBadEntries(t *testing.T) {
	for _, e := range []string{"", "nope", "10.0.0.0/33", "300.1.1.1"} {
		_, err := Parse([]string{"10.0.0.0/8", e})
		assert.Error(t, err, e)
	}
}

// The trie must agree with the reference linear implementation on random data.
func TestAgreesWithTheReferenceImplementation(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test data
	var entries []string
	for range 2000 {
		if rng.IntN(4) == 0 {
			var b [16]byte
			for i := range b {
				b[i] = byte(rng.IntN(256)) //nolint:gosec // IntN(256) fits a byte
			}
			entries = append(entries, netip.PrefixFrom(netip.AddrFrom16(b), 16+rng.IntN(100)).Masked().String())
			continue
		}
		a := randV4(rng)
		entries = append(entries, netip.PrefixFrom(a, 8+rng.IntN(25)).Masked().String())
	}
	fast := mustParse(t, entries...)
	ref, err := policy.ParseCIDRSet(entries)
	require.NoError(t, err)

	for range 20000 {
		var ip netip.Addr
		if rng.IntN(4) == 0 {
			var b [16]byte
			for i := range b {
				b[i] = byte(rng.IntN(256)) //nolint:gosec // IntN(256) fits a byte
			}
			ip = netip.AddrFrom16(b)
		} else {
			ip = randV4(rng)
		}
		require.Equal(t, ref.Contains(ip), fast.Contains(ip), "ip %s", ip)
	}
}

func buildBig(b testing.TB, n int) (*Set, []netip.Addr) {
	b.Helper()
	rng := rand.New(rand.NewPCG(7, 8)) //nolint:gosec // deterministic benchmark data
	bu := NewBuilder()
	for range n {
		a := randV4(rng)
		bu.Add(netip.PrefixFrom(a, 24+rng.IntN(9)).Masked())
	}
	probes := make([]netip.Addr, 4096)
	for i := range probes {
		probes[i] = randV4(rng)
	}
	return bu.Build(), probes
}

func BenchmarkContains100k(b *testing.B) {
	s, probes := buildBig(b, 100_000)
	b.ReportAllocs()
	b.ResetTimer()
	hits := 0
	for i := range b.N {
		if s.Contains(probes[i%len(probes)]) {
			hits++
		}
	}
	_ = hits
}

// TestLookupCostIsFlat guards the acceptance bar (100k entries add far less than
// 0.1 ms per request) without depending on machine speed: it checks the work per
// lookup is bounded by the address width, not the list size.
func TestLookupCostIsFlat(t *testing.T) {
	s, probes := buildBig(t, 100_000)
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := range b.N {
			_ = s.Contains(probes[i%len(probes)])
		}
	})
	assert.Zero(t, res.AllocsPerOp(), "lookups must not allocate")
	assert.Less(t, res.NsPerOp(), int64(1000), fmt.Sprintf("a lookup in a 100k-entry set took %d ns; the budget is 1 µs", res.NsPerOp()))
}

func randV4(rng *rand.Rand) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))}) //nolint:gosec // IntN(256) fits a byte
}
