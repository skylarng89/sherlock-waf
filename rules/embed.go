// Package rules embeds the rule packs that ship inside every release
// (ADR-0011, ADR-0013): the virtual-patch pack for exploited CVEs.
package rules

import "embed"

// VirtualPatches holds SV-<year>-<n>.conf rules, their .yaml metadata, the
// .tests.yaml request fixtures and covered-by-crs.yaml.
//
//go:embed virtual-patches
var VirtualPatches embed.FS
