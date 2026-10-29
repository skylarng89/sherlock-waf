// Package vpatch loads the virtual-patch pack (ADR-0013): SecLang rules for
// actively exploited CVEs with metadata, plus the catalogue of CVEs that the
// OWASP CRS already blocks. The pack is embedded in the binary; nothing is
// read from disk or the network at run time.
package vpatch

import (
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/skylarng89/sherlock-waf/rules"
)

// Reserved rule id range for the pack (ADR-0013).
const (
	MinRuleID = 9_500_000
	MaxRuleID = 9_599_999
)

// Verification states of a patch.
const (
	// VerifiedSynthetic: the exploit request was rebuilt from public technical
	// write-ups and is blocked in tests; it was not replayed against a
	// vulnerable instance of the product.
	VerifiedSynthetic = "synthetic"
	// VerifiedProduct: replayed against a vulnerable product instance.
	VerifiedProduct = "product-verified"
)

// Patch is one virtual patch: a rule file and its metadata.
type Patch struct {
	ID       string   `yaml:"id" json:"id"`
	Title    string   `yaml:"title" json:"title"`
	CVEs     []string `yaml:"cves" json:"cves"`
	Vendor   string   `yaml:"vendor" json:"vendor"`
	Product  string   `yaml:"product" json:"product"`
	Versions string   `yaml:"versions" json:"versions"`
	Severity string   `yaml:"severity" json:"severity"` // low | medium | high | critical
	CVSS     float64  `yaml:"cvss" json:"cvss"`
	KEV      bool     `yaml:"kev" json:"kev"`
	KEVAdded string   `yaml:"kev_added,omitempty" json:"kev_added,omitempty"`
	// Stacks lists the declared stacks that activate the patch. Empty means
	// generic: it is low-false-positive and active everywhere the pack is on.
	Stacks             []string `yaml:"stacks" json:"stacks"`
	References         []string `yaml:"references" json:"references"`
	FalsePositiveNotes string   `yaml:"false_positive_notes" json:"false_positive_notes"`
	Verification       string   `yaml:"verification" json:"verification"`
	AddedIn            string   `yaml:"added_in" json:"added_in"`
	RuleIDs            []int    `yaml:"rule_ids" json:"rule_ids"`

	// Rules is the SecLang text from <id>.conf; not part of the catalogue API.
	Rules string `yaml:"-" json:"-"`
	// Tests holds the request fixtures from <id>.tests.yaml.
	Tests TestSet `yaml:"-" json:"-"`
}

// Generic reports whether the patch applies without a declared stack.
func (p Patch) Generic() bool { return len(p.Stacks) == 0 }

// TestSet are the exploit requests that must be blocked and the benign
// requests that must not.
type TestSet struct {
	Positive []TestRequest `yaml:"positive"`
	Negative []TestRequest `yaml:"negative"`
}

// TestRequest is a synthetic HTTP request.
type TestRequest struct {
	Name        string            `yaml:"name"`
	Method      string            `yaml:"method"`
	Path        string            `yaml:"path"`
	ContentType string            `yaml:"content_type"`
	Headers     map[string]string `yaml:"headers"`
	Body        string            `yaml:"body"`
}

// CoveredCVE records a CVE that CRS already blocks at PL1, so the dashboard
// can still show it as covered (process: docs/security/virtual-patching-process.md).
type CoveredCVE struct {
	CVE      string   `yaml:"cve" json:"cve"`
	Product  string   `yaml:"product" json:"product"`
	KEV      bool     `yaml:"kev" json:"kev"`
	KEVAdded string   `yaml:"kev_added,omitempty" json:"kev_added,omitempty"`
	Severity string   `yaml:"severity" json:"severity"`
	CRSRules []string `yaml:"crs_rules" json:"crs_rules"`
	Note     string   `yaml:"note,omitempty" json:"note,omitempty"`
	// Test is the request that the CRS-only regression test replays.
	Test TestRequest `yaml:"test" json:"-"`
}

var (
	patchIDRE  = regexp.MustCompile(`^SV-\d{4}-\d{4}$`)
	cveRE      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	idInRule   = regexp.MustCompile(`(?:^|[\s",])id:(\d+)`)
	severities = []string{"low", "medium", "high", "critical"}

	loadOnce sync.Once
	loaded   pack
	loadErr  error
)

type pack struct {
	patches []Patch
	byID    map[string]int
	covered []CoveredCVE
}

// Load parses the embedded pack. It is cached; an error means the build is
// broken and is also caught by the package tests.
func load() (pack, error) {
	loadOnce.Do(func() { loaded, loadErr = parse(rules.VirtualPatches, "virtual-patches") })
	return loaded, loadErr
}

func strictYAML(b []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func parse(fsys fs.FS, dir string) (pack, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return pack{}, fmt.Errorf("reading virtual patch pack: %w", err)
	}
	var p pack
	seenRules := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") || name == "covered-by-crs.yaml" || strings.HasSuffix(name, ".tests.yaml") {
			continue
		}
		id := strings.TrimSuffix(name, ".yaml")
		read := func(ext string) ([]byte, error) { return fs.ReadFile(fsys, dir+"/"+id+ext) }

		meta, err := read(".yaml")
		if err != nil {
			return pack{}, fmt.Errorf("reading %s: %w", name, err)
		}
		var patch Patch
		if err := strictYAML(meta, &patch); err != nil {
			return pack{}, fmt.Errorf("parsing %s: %w", name, err)
		}
		conf, err := read(".conf")
		if err != nil {
			return pack{}, fmt.Errorf("patch %s has no rule file: %w", id, err)
		}
		patch.Rules = string(conf)
		if tb, err := read(".tests.yaml"); err == nil {
			if err := strictYAML(tb, &patch.Tests); err != nil {
				return pack{}, fmt.Errorf("parsing %s.tests.yaml: %w", id, err)
			}
		}
		if err := patch.validate(id); err != nil {
			return pack{}, err
		}
		for _, rid := range patch.RuleIDs {
			if other, dup := seenRules[rid]; dup {
				return pack{}, fmt.Errorf("rule id %d used by both %s and %s", rid, other, id)
			}
			seenRules[rid] = id
		}
		p.patches = append(p.patches, patch)
	}
	sort.Slice(p.patches, func(i, j int) bool { return p.patches[i].ID < p.patches[j].ID })
	p.byID = make(map[string]int, len(p.patches))
	for i, pt := range p.patches {
		p.byID[pt.ID] = i
	}

	if b, err := fs.ReadFile(fsys, dir+"/covered-by-crs.yaml"); err == nil {
		var doc struct {
			Covered []CoveredCVE `yaml:"covered"`
		}
		if err := strictYAML(b, &doc); err != nil {
			return pack{}, fmt.Errorf("parsing covered-by-crs.yaml: %w", err)
		}
		for _, c := range doc.Covered {
			if !cveRE.MatchString(c.CVE) {
				return pack{}, fmt.Errorf("covered-by-crs.yaml: %q is not a CVE id", c.CVE)
			}
		}
		p.covered = doc.Covered
	}
	return p, nil
}

func (p Patch) validate(file string) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("patch %s: %s", file, fmt.Sprintf(format, args...))
	}
	switch {
	case !patchIDRE.MatchString(p.ID) || p.ID != file:
		return fail("id %q must equal the file name and look like SV-2021-0001", p.ID)
	case p.Title == "" || p.Product == "" || p.Vendor == "":
		return fail("title, vendor and product are required")
	case len(p.CVEs) == 0:
		return fail("at least one CVE is required")
	case !slices.Contains(severities, p.Severity):
		return fail("severity must be one of %v", severities)
	case p.CVSS < 0 || p.CVSS > 10:
		return fail("cvss must be 0-10")
	case p.Verification != VerifiedSynthetic && p.Verification != VerifiedProduct:
		return fail("verification must be %q or %q", VerifiedSynthetic, VerifiedProduct)
	case len(p.References) == 0:
		return fail("at least one reference is required")
	case p.FalsePositiveNotes == "":
		return fail("false_positive_notes is required")
	case p.AddedIn == "":
		return fail("added_in (pack version) is required")
	case len(p.Tests.Positive) == 0 || len(p.Tests.Negative) == 0:
		return fail("a positive exploit test and a benign negative test are required")
	case len(p.RuleIDs) == 0:
		return fail("rule_ids is required")
	}
	for _, c := range p.CVEs {
		if !cveRE.MatchString(c) {
			return fail("%q is not a CVE id", c)
		}
	}
	found := map[int]bool{}
	for _, m := range idInRule.FindAllStringSubmatch(p.Rules, -1) {
		var n int
		_, _ = fmt.Sscanf(m[1], "%d", &n)
		found[n] = true
	}
	for id := range found {
		if id < MinRuleID || id > MaxRuleID {
			return fail("rule id %d is outside the reserved range %d-%d", id, MinRuleID, MaxRuleID)
		}
		if !slices.Contains(p.RuleIDs, id) {
			return fail("rule id %d is in the .conf but not listed in rule_ids", id)
		}
	}
	for _, id := range p.RuleIDs {
		if !found[id] {
			return fail("rule_ids lists %d but the .conf does not define it", id)
		}
	}
	return nil
}

// All returns the pack ordered by id.
func All() ([]Patch, error) {
	p, err := load()
	return slices.Clone(p.patches), err
}

// Get returns one patch.
func Get(id string) (Patch, bool) {
	p, err := load()
	if err != nil {
		return Patch{}, false
	}
	i, ok := p.byID[id]
	if !ok {
		return Patch{}, false
	}
	return p.patches[i], true
}

// Covered returns the CVEs CRS already blocks.
func Covered() ([]CoveredCVE, error) {
	p, err := load()
	return slices.Clone(p.covered), err
}

// Active reports whether a patch is active for a site: the pack must be
// enabled, the patch not disabled, and a product-specific patch needs one of
// its stacks declared. Undeclared stacks ("auto") activate generic patches
// only, so a WordPress rule never runs on a site that is not WordPress.
func (p Patch) Active(enabled bool, disabled, declared []string) bool {
	if !enabled || slices.Contains(disabled, p.ID) {
		return false
	}
	if p.Generic() {
		return true
	}
	return slices.ContainsFunc(declared, func(s string) bool { return slices.Contains(p.Stacks, s) })
}

// Select returns the ids of the patches active for the given policy, sorted.
func Select(enabled bool, disabled, declared []string) ([]string, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, p := range all {
		if p.Active(enabled, disabled, declared) {
			ids = append(ids, p.ID)
		}
	}
	return ids, nil
}

// Directives renders the SecLang of the given patches in id order. Unknown
// ids are skipped (a retired patch must not stop a configuration loading).
func Directives(ids []string) (string, error) {
	p, err := load()
	if err != nil {
		return "", err
	}
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	var b strings.Builder
	for _, id := range slices.Compact(sorted) {
		i, ok := p.byID[id]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "# %s\n%s\n", id, strings.TrimRight(p.patches[i].Rules, "\n"))
	}
	return b.String(), nil
}

// IsRuleID reports whether a rule id belongs to the pack's reserved range.
func IsRuleID(id int) bool { return id >= MinRuleID && id <= MaxRuleID }

// commonStacks are suggested stack names besides those the pack uses.
var commonStacks = []string{"apache", "django", "drupal", "iis", "java", "joomla", "laravel", "magento", "nginx", "nodejs", "php", "rails", "spring", "tomcat", "wordpress"}

// KnownStacks lists the stack names the dashboard can offer: the pack's own
// plus common ones. Declaring any other name is allowed.
func KnownStacks() []string {
	set := map[string]struct{}{}
	for _, s := range commonStacks {
		set[s] = struct{}{}
	}
	all, _ := All()
	for _, p := range all {
		for _, s := range p.Stacks {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}
