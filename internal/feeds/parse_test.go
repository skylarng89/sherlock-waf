package feeds

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNetsetHandlesBothFormats(t *testing.T) {
	firehol := "# comment\n1.2.3.0/24\n\n5.6.7.8\n2001:db8::/32\nnot-an-ip\n"
	drop := "; Spamhaus DROP List\n198.51.100.0/24 ; SBL12345\n203.0.113.0/25;SBL9\n"
	ps, err := ParseNetset([]byte(firehol))
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24"), netip.MustParsePrefix("5.6.7.8/32"), netip.MustParsePrefix("2001:db8::/32")}, ps, "bad lines are skipped, not fatal")
	ps, err = ParseNetset([]byte(drop))
	require.NoError(t, err)
	assert.Len(t, ps, 2)

	_, err = ParseNetset([]byte("# nothing here\n"))
	assert.Error(t, err, "an empty list is treated as a failed download, not as 'allow everyone'")
	_, err = ParseNetset([]byte("<html>rate limited</html>\n"))
	assert.Error(t, err)
}

func TestParseDBIPCountryAndLookup(t *testing.T) {
	csvData := "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n\"1.0.1.0\",\"1.0.3.255\",\"CN\"\n\"2001:db8::\",\"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\",\"nl\"\nbad,row\n\"x\",\"y\",\"ZZ\"\n"
	for name, data := range map[string][]byte{"plain": []byte(csvData), "gzip": gz(t, csvData)} {
		db, err := ParseDBIPCountry(data)
		require.NoError(t, err, name)
		assert.Equal(t, 3, db.Len(), name)
		for ip, want := range map[string]string{"1.0.0.1": "AU", "1.0.0.255": "AU", "1.0.1.0": "CN", "1.0.3.255": "CN", "2001:db8::5": "NL", "::ffff:1.0.0.9": "AU"} {
			cc, ok := db.Country(netip.MustParseAddr(ip))
			assert.True(t, ok, "%s %s", name, ip)
			assert.Equal(t, want, cc, "%s %s", name, ip)
		}
		for _, ip := range []string{"0.255.255.255", "1.0.4.0", "9.9.9.9", "2001:db9::1"} {
			_, ok := db.Country(netip.MustParseAddr(ip))
			assert.False(t, ok, "%s %s", name, ip)
		}
	}
	_, err := ParseDBIPCountry([]byte("garbage\n"))
	assert.Error(t, err)
	_, err = ParseDBIPCountry([]byte{0x1f, 0x8b, 0x00})
	assert.Error(t, err, "corrupt gzip")
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}
