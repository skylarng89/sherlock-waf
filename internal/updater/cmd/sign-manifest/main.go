// Command sign-manifest signs dist/release-manifest.json for `sherlock update`.
// The private key (base64 seed) is read from the file named by the first
// argument, never from a flag or the environment:
//
//	go run ./internal/updater/cmd/sign-manifest <key file> <manifest> [<manifest>.sig]
//	go run ./internal/updater/cmd/sign-manifest -public <key file>     (prints the public key to commit)
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/updater"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sign-manifest:", err)
		os.Exit(1)
	}
}

func readSeed(path string) ([]byte, error) {
	b64, err := os.ReadFile(path) //nolint:gosec // operator-supplied path in a release tool
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key file must hold a base64 %d-byte Ed25519 seed", ed25519.SeedSize)
	}
	return seed, nil
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "-public" {
		seed, err := readSeed(args[1])
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)))
		return nil
	}
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("usage: sign-manifest <key file> <manifest> [<signature out>] | sign-manifest -public <key file>")
	}
	seed, err := readSeed(args[0])
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(args[1]) //nolint:gosec // operator-supplied path in a release tool
	if err != nil {
		return err
	}
	out := args[1] + ".sig"
	if len(args) == 3 {
		out = args[2]
	}
	return os.WriteFile(out, updater.Sign(ed25519.NewKeyFromSeed(seed), manifest), 0o644) //nolint:gosec // a public signature
}
