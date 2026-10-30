package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIP(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"203.0.113.9", "203.0.113.9", false},
		{" 203.0.113.9 ", "203.0.113.9", false},
		{"203.0.113.9:8080", "203.0.113.9", false},
		{"[2001:db8::1]:443", "2001:db8::1", false},
		{"[2001:db8::1]", "2001:db8::1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"fe80::1%eth0", "fe80::1", false},
		{"::ffff:192.0.2.1", "192.0.2.1", false},
		{"", "", true},
		{"unknown", "", true},
		{"1.2.3.4.5", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseIP(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestParseRemoteAddr(t *testing.T) {
	a, err := ParseRemoteAddr("198.51.100.4:51234")
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.4", a.String())

	a, err = ParseRemoteAddr("[2001:db8::2]:1")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::2", a.String())

	_, err = ParseRemoteAddr("not-an-ip")
	require.Error(t, err)
}

func TestCIDRSet(t *testing.T) {
	set, err := ParseCIDRSet([]string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "::ffff:172.16.0.0/112"})
	require.NoError(t, err)
	assert.Equal(t, 4, set.Len())

	tests := map[string]bool{
		"10.255.1.1":      true,
		"11.0.0.1":        false,
		"192.0.2.7":       true,
		"192.0.2.8":       false,
		"2001:db8::99":    true,
		"2001:db9::1":     false,
		"::ffff:10.1.1.1": true,
		"172.16.0.5":      true,
		"172.17.0.5":      false,
	}
	for in, want := range tests {
		ip, err := ParseIP(in)
		require.NoError(t, err)
		assert.Equal(t, want, set.Contains(ip), in)
	}
}

func TestCIDRSetErrorsAndZeroValue(t *testing.T) {
	_, err := ParseCIDRSet([]string{"10.0.0.0/33"})
	require.Error(t, err)
	_, err = ParseCIDRSet([]string{"nope"})
	require.Error(t, err)

	var zero CIDRSet
	ip, _ := ParseIP("1.1.1.1")
	assert.False(t, zero.Contains(ip))
}

func FuzzParseIP(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "[::1]:80", "fe80::1%x", "", "::ffff:1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = ParseIP(s) })
}
