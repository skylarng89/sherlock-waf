// Command mmdbfixture writes the small MaxMind-format country database used by
// the feeds tests. It runs from the tools module so that mmdbwriter never
// becomes a dependency of the main module. Regenerate with:
//
//	cd tools && go run ./cmd/mmdbfixture -type GeoLite2-Country -out ../internal/feeds/testdata/GeoLite2-Country-test.mmdb
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// fixtureRanges use documentation address space (RFC 5737, RFC 3849) so the
// fixture can never be mistaken for real geolocation data.
var fixtureRanges = []struct {
	cidr string
	iso  string
}{
	{"198.51.100.0/24", "AU"},
	{"203.0.113.0/24", "DE"},
	{"2001:db8::/32", "JP"},
}

func main() {
	dbType := flag.String("type", "GeoLite2-Country", "database_type written to the metadata")
	out := flag.String("out", "", "output .mmdb path")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            *dbType,
		Description:             map[string]string{"en": "Sherlock test fixture"},
		IncludeReservedNetworks: true, // the ranges below are documentation space
	})
	if err != nil {
		log.Fatalf("creating writer: %v", err)
	}
	for _, r := range fixtureRanges {
		_, network, err := net.ParseCIDR(r.cidr)
		if err != nil {
			log.Fatalf("parsing %s: %v", r.cidr, err)
		}
		record := mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(r.iso)},
		}
		if err := w.Insert(network, record); err != nil {
			log.Fatalf("inserting %s: %v", r.cidr, err)
		}
	}

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644) //nolint:gosec // developer tool writing a fixture
	if err != nil {
		log.Fatalf("creating %s: %v", *out, err)
	}
	if _, err := w.WriteTo(f); err != nil {
		_ = f.Close()
		log.Fatalf("writing %s: %v", *out, err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("closing %s: %v", *out, err)
	}
	fmt.Println("wrote", *out)
}
