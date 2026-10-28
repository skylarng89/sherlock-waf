package config

import (
	"slices"
	"sort"
	"strings"
)

// Policy sources reported in EffectivePolicy.Sources.
const (
	SourceDefault = "default"
	SourceGlobal  = "global"
	SourceSite    = "site"
	SourceDerived = "derived"
)

// EndpointSource names an endpoint layer in EffectivePolicy.Sources.
func EndpointSource(id string) string { return "endpoint:" + id }

// EffectivePolicy is a fully resolved policy: no field is unset.
type EffectivePolicy struct {
	Mode      Mode
	FailMode  FailMode
	WAF       EffectiveWAF
	BlockPage EffectiveBlockPage
	// Sources maps a dotted field name (e.g. "waf.paranoia_level") to the
	// layer that supplied its value.
	Sources map[string]string
}

// EffectiveWAF is the resolved WAF tuning.
type EffectiveWAF struct {
	Enabled                  bool
	ParanoiaLevel            int
	BlockingParanoiaLevel    int
	InboundThreshold         int
	OutboundThreshold        int
	OutboundInspection       bool
	MaxBodyBytes             int64
	SkipInspectionExtensions []string
}

// EffectiveBlockPage is the resolved block page selection.
type EffectiveBlockPage struct {
	TemplateID string
}

// EffectivePolicy resolves defaults → global → site → endpoint. ep may be
// nil for the site-default policy. Resolution is done once at compile time.
func (r *Root) EffectivePolicy(s *Site, ep *Endpoint) EffectivePolicy {
	eff := EffectivePolicy{
		Mode: ModeDetect,
		WAF: EffectiveWAF{
			Enabled:                  true,
			ParanoiaLevel:            1,
			InboundThreshold:         DefaultInboundThreshold,
			OutboundThreshold:        DefaultOutboundThreshold,
			MaxBodyBytes:             DefaultMaxBodyBytes,
			SkipInspectionExtensions: DefaultSkipInspectionExtensions(),
		},
		BlockPage: EffectiveBlockPage{TemplateID: DefaultBlockPageTemplate},
		Sources:   map[string]string{},
	}
	for _, f := range []string{
		"mode", "waf.enabled", "waf.paranoia_level", "waf.inbound_threshold",
		"waf.outbound_threshold", "waf.outbound_inspection", "waf.max_body_bytes",
		"waf.skip_inspection_extensions", "block_page.template_id",
	} {
		eff.Sources[f] = SourceDefault
	}

	layers := []struct {
		name string
		pol  *Policy
	}{{SourceGlobal, &r.Global.Defaults}}
	if s != nil {
		layers = append(layers, struct {
			name string
			pol  *Policy
		}{SourceSite, &s.Policy})
	}
	if ep != nil {
		layers = append(layers, struct {
			name string
			pol  *Policy
		}{EndpointSource(ep.ID), &ep.Policy})
	}

	var failSet, blockingSet bool
	for _, l := range layers {
		eff.apply(l.pol, l.name, &failSet, &blockingSet)
	}
	if !failSet {
		eff.FailMode = FailOpen
		if eff.Mode == ModeBlock {
			eff.FailMode = FailClosed
		}
		eff.Sources["fail_mode"] = SourceDerived
	}
	if !blockingSet {
		eff.WAF.BlockingParanoiaLevel = eff.WAF.ParanoiaLevel
		eff.Sources["waf.blocking_paranoia_level"] = SourceDerived
	}
	return eff
}

func (e *EffectivePolicy) apply(p *Policy, src string, failSet, blockingSet *bool) {
	set := func(field string) { e.Sources[field] = src }
	if p.Mode != nil {
		e.Mode = *p.Mode
		set("mode")
	}
	if p.FailMode != nil {
		e.FailMode, *failSet = *p.FailMode, true
		set("fail_mode")
	}
	if p.BlockPage != nil && p.BlockPage.TemplateID != nil {
		e.BlockPage.TemplateID = *p.BlockPage.TemplateID
		set("block_page.template_id")
	}
	w := p.WAF
	if w == nil {
		return
	}
	if w.Enabled != nil {
		e.WAF.Enabled = *w.Enabled
		set("waf.enabled")
	}
	if w.ParanoiaLevel != nil {
		e.WAF.ParanoiaLevel = *w.ParanoiaLevel
		set("waf.paranoia_level")
	}
	if w.BlockingParanoiaLevel != nil {
		e.WAF.BlockingParanoiaLevel, *blockingSet = *w.BlockingParanoiaLevel, true
		set("waf.blocking_paranoia_level")
	}
	if w.InboundThreshold != nil {
		e.WAF.InboundThreshold = *w.InboundThreshold
		set("waf.inbound_threshold")
	}
	if w.OutboundThreshold != nil {
		e.WAF.OutboundThreshold = *w.OutboundThreshold
		set("waf.outbound_threshold")
	}
	if w.OutboundInspection != nil {
		e.WAF.OutboundInspection = *w.OutboundInspection
		set("waf.outbound_inspection")
	}
	if w.MaxBodyBytes != nil {
		e.WAF.MaxBodyBytes = *w.MaxBodyBytes
		set("waf.max_body_bytes")
	}
	if w.SkipInspectionExtensions != nil {
		e.WAF.SkipInspectionExtensions = slices.Clone(w.SkipInspectionExtensions)
		set("waf.skip_inspection_extensions")
	}
}

// Match classes, highest precedence first.
const (
	classExact  = 2
	classPrefix = 1 // path_prefix and path_glob
)

// pattern returns the match class, the pattern text and its specificity.
func (m EndpointMatch) pattern() (class int, pat string) {
	switch {
	case m.Path != "":
		return classExact, m.Path
	case m.PathPrefix != "":
		return classPrefix, m.PathPrefix
	default:
		return classPrefix, m.PathGlob
	}
}

type precedenceKey struct {
	class       int
	specificity int
	methodBound bool
}

func (m EndpointMatch) key() precedenceKey {
	c, p := m.pattern()
	return precedenceKey{class: c, specificity: len(p), methodBound: len(m.Methods) > 0}
}

func (k precedenceKey) less(o precedenceKey) bool { // true when k outranks o
	if k.class != o.class {
		return k.class > o.class
	}
	if k.specificity != o.specificity {
		return k.specificity > o.specificity
	}
	return k.methodBound && !o.methodBound
}

// literalHead is the pattern up to its first glob metacharacter.
func literalHead(pat string) string {
	if i := strings.IndexAny(pat, `*?[\`); i >= 0 {
		return pat[:i]
	}
	return pat
}

// ambiguousWith reports equal-precedence matches that can select the same
// request. Overlap detection is conservative: literal heads that are
// prefix-compatible are assumed to overlap.
func (m EndpointMatch) ambiguousWith(o EndpointMatch) bool {
	if m.key() != o.key() {
		return false
	}
	if len(m.Methods) > 0 && !slices.ContainsFunc(m.Methods, func(v string) bool { return slices.Contains(o.Methods, v) }) {
		return false
	}
	c, a := m.pattern()
	_, b := o.pattern()
	if c == classExact {
		return a == b
	}
	ha, hb := literalHead(a), literalHead(b)
	return strings.HasPrefix(ha, hb) || strings.HasPrefix(hb, ha)
}

// OrderedEndpoints returns the site's endpoints most specific first, ties
// broken by declaration order. The compiler emits subroutes in this order.
func (s *Site) OrderedEndpoints() []Endpoint {
	out := slices.Clone(s.Endpoints)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Match.key().less(out[j].Match.key()) })
	return out
}
