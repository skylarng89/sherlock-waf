// Package feeds keeps the data-plane lookup data fresh in the background:
// the GeoIP country database, reputation lists and the CrowdSec decision
// stream. A failed refresh keeps the previous data and is reported, never
// applied half-way, and every swap is atomic so requests are never dropped.
package feeds

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// maxListEntries bounds one reputation list (FireHOL level1 has ~4,000 prefixes).
const maxListEntries = 500_000

// ParseNetset reads a netset or DROP-style list: one CIDR or address per line,
// '#' and ';' starting comments (Spamhaus DROP writes "1.2.3.0/24 ; SBL123").
func ParseNetset(data []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := policy.ParsePrefix(line)
		if err != nil {
			continue // one odd line must not discard a whole list
		}
		out = append(out, p)
		if len(out) > maxListEntries {
			return nil, fmt.Errorf("list has more than %d entries", maxListEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading list: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("list contained no valid entries")
	}
	return out, nil
}

type geoRange struct {
	start, end netip.Addr
	cc         string
}

// RangeDB is an immutable country database: sorted, non-overlapping address ranges.
type RangeDB struct {
	v4, v6 []geoRange
}

// Country implements acl.CountryLookup.
func (d *RangeDB) Country(ip netip.Addr) (string, bool) {
	ip = ip.WithZone("").Unmap()
	rs := d.v6
	if ip.Is4() {
		rs = d.v4
	}
	i := sort.Search(len(rs), func(i int) bool { return rs[i].end.Compare(ip) >= 0 })
	if i < len(rs) && rs[i].start.Compare(ip) <= 0 {
		return rs[i].cc, true
	}
	return "", false
}

// Len is the number of ranges.
func (d *RangeDB) Len() int { return len(d.v4) + len(d.v6) }

// ParseDBIPCountry reads the DB-IP Lite country CSV ("start","end","CC" per
// line), optionally gzip-compressed.
func ParseDBIPCountry(data []byte) (*RangeDB, error) {
	var r io.Reader = bytes.NewReader(data)
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("opening gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		r = io.LimitReader(zr, 256<<20)
	}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	db := &RangeDB{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading csv: %w", err)
		}
		if len(rec) < 3 {
			continue
		}
		a, err1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		b, err2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		cc := strings.ToUpper(strings.TrimSpace(rec[2]))
		if err1 != nil || err2 != nil || len(cc) != 2 || a.Is4() != b.Is4() {
			continue
		}
		if a.Is4() {
			db.v4 = append(db.v4, geoRange{a, b, cc})
		} else {
			db.v6 = append(db.v6, geoRange{a, b, cc})
		}
	}
	if db.Len() == 0 {
		return nil, errors.New("no usable ranges in the database")
	}
	byStart := func(x, y geoRange) int { return x.start.Compare(y.start) }
	slices.SortFunc(db.v4, byStart)
	slices.SortFunc(db.v6, byStart)
	return db, nil
}
