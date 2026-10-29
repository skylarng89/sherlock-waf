// Command schemagen writes the generated event JSON Schema. Run it with
// `make gen`; CI fails if the committed file differs.
package main

import (
	"fmt"
	"os"

	"github.com/skylarng89/sherlock-waf/internal/events"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: schemagen <output file>")
		os.Exit(2)
	}
	b, err := events.Schema()
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemagen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil { //nolint:gosec // generated public docs file
		fmt.Fprintln(os.Stderr, "schemagen:", err)
		os.Exit(1)
	}
}
