package feeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// MaxMindCountry is an immutable MaxMind DB country database (GeoLite2-Country
// or GeoIP2-Country). It is safe for concurrent lookups.
type MaxMindCountry struct {
	r     *maxminddb.Reader
	nodes uint
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// ParseMaxMindCountry opens an in-memory .mmdb and rejects any database whose
// database_type is not a country database, so a City or ASN file placed in the
// geoip directory can never be loaded as country data.
func ParseMaxMindCountry(data []byte) (*MaxMindCountry, error) {
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, fmt.Errorf("opening mmdb: %w", err)
	}
	if !strings.Contains(r.Metadata.DatabaseType, "Country") {
		_ = r.Close()
		return nil, fmt.Errorf("mmdb database_type %q is not a country database", r.Metadata.DatabaseType)
	}
	return &MaxMindCountry{r: r, nodes: r.Metadata.NodeCount}, nil
}

// Country implements acl.CountryLookup.
func (d *MaxMindCountry) Country(ip netip.Addr) (string, bool) {
	ip = ip.WithZone("").Unmap()
	res := d.r.Lookup(ip)
	if !res.Found() {
		return "", false
	}
	var rec countryRecord
	if err := res.Decode(&rec); err != nil || rec.Country.ISOCode == "" {
		return "", false
	}
	return strings.ToUpper(rec.Country.ISOCode), true
}

// Len reports the search-tree node count, the closest analogue of the DB-IP range count.
func (d *MaxMindCountry) Len() int { return int(d.nodes) }

// extractMMDB returns the GeoLite2-Country .mmdb from a MaxMind tar.gz. Entries
// are matched by base name only and their names never become file paths. The
// decompressed stream and the entry are each capped, so a gzip bomb ends with
// an error instead of exhausting memory.
func extractMMDB(archive []byte, maxStream, maxEntry int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("opening archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(io.LimitReader(zr, maxStream))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != maxMindEntryName {
			continue
		}
		if hdr.Size > maxEntry {
			return nil, fmt.Errorf("%s in archive is larger than %d bytes", maxMindEntryName, maxEntry)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxEntry+1))
		if err != nil {
			return nil, fmt.Errorf("reading %s from archive: %w", maxMindEntryName, err)
		}
		if int64(len(body)) > maxEntry {
			return nil, fmt.Errorf("%s in archive is larger than %d bytes", maxMindEntryName, maxEntry)
		}
		return body, nil
	}
	return nil, fmt.Errorf("archive has no %s entry", maxMindEntryName)
}
