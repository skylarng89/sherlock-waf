// Package ipset is an immutable set of IP prefixes for per-request lookups:
// a binary radix trie over the address bits, so a lookup costs at most 32
// (IPv4) or 128 (IPv6) steps whatever the number of entries, with no
// allocation. Lists of 100,000 entries and more are expected (reputation feeds).
package ipset

import (
	"fmt"
	"net/netip"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

type node struct {
	child [2]uint32 // index into nodes; 0 means none (node 0 is a root, never a child)
	end   bool      // a prefix ends here: everything below matches
}

// Set is an immutable prefix set. The zero value matches nothing.
type Set struct {
	v4, v6 []node // each slice's element 0 is its root
	n      int
}

// Builder accumulates prefixes. It is not safe for concurrent use.
type Builder struct {
	s Set
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{s: Set{v4: make([]node, 1), v6: make([]node, 1)}}
}

// Add inserts a prefix. Prefixes already covered by a shorter one are absorbed.
func (b *Builder) Add(p netip.Prefix) {
	a := p.Addr().Unmap()
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits = max(bits-96, 0)
	}
	nodes := &b.s.v6
	if a.Is4() {
		nodes = &b.s.v4
	}
	raw := a.As16()
	off := 0
	if a.Is4() {
		off = 12
	}
	idx := uint32(0)
	for i := range bits {
		if (*nodes)[idx].end {
			return // covered by a shorter prefix already
		}
		bit := (raw[off+i/8] >> (7 - uint(i%8))) & 1
		next := (*nodes)[idx].child[bit]
		if next == 0 {
			*nodes = append(*nodes, node{})
			next = uint32(len(*nodes) - 1) //nolint:gosec // bounded by the entry count times 128
			(*nodes)[idx].child[bit] = next
		}
		idx = next
	}
	(*nodes)[idx].end = true
	(*nodes)[idx].child = [2]uint32{} // everything below is now redundant (orphaned nodes are dropped by Build)
}

// Build freezes the set.
func (b *Builder) Build() *Set {
	s := &Set{v4: compact(b.s.v4), v6: compact(b.s.v6)}
	s.n = countEnds(s.v4) + countEnds(s.v6)
	return s
}

// compact rebuilds nodes keeping only those reachable from the root, which
// drops the subtrees a shorter prefix absorbed and closes any gaps.
func compact(old []node) []node {
	out := make([]node, 1, len(old))
	var walk func(from, to uint32)
	walk = func(from, to uint32) {
		out[to].end = old[from].end
		for bit := range 2 {
			c := old[from].child[bit]
			if c == 0 {
				continue
			}
			out = append(out, node{})
			idx := uint32(len(out) - 1) //nolint:gosec // bounded by the entry count times 128
			out[to].child[bit] = idx
			walk(c, idx)
		}
	}
	walk(0, 0)
	return out
}

func countEnds(nodes []node) int {
	n := 0
	for _, nd := range nodes {
		if nd.end {
			n++
		}
	}
	return n
}

// Parse builds a set from CIDR or bare-IP strings.
func Parse(entries []string) (*Set, error) {
	b := NewBuilder()
	for i, e := range entries {
		p, err := policy.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		b.Add(p)
	}
	return b.Build(), nil
}

// Contains reports whether ip is covered by any prefix. A nil Set matches nothing.
func (s *Set) Contains(ip netip.Addr) bool {
	if s == nil || len(s.v4) == 0 {
		return false
	}
	ip = ip.WithZone("").Unmap()
	nodes := s.v6
	off, bits := 0, 128
	if ip.Is4() {
		nodes, off, bits = s.v4, 12, 32
	}
	raw := ip.As16()
	idx := uint32(0)
	for i := range bits {
		if nodes[idx].end {
			return true
		}
		bit := (raw[off+i/8] >> (7 - uint(i%8))) & 1
		idx = nodes[idx].child[bit]
		if idx == 0 {
			return false
		}
	}
	return nodes[idx].end
}

// Len is the number of distinct (non-redundant) prefixes.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return s.n
}
