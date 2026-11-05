package config

// RedactedPlaceholder replaces secret values in API responses. A client that
// sends it back (or omits the field) keeps the stored value: see RestoreRedacted.
// It is part of the control-plane API contract (docs/user/control-plane.md).
const RedactedPlaceholder = "<redacted>"

// redactPolicy returns p with the password-gate hash replaced. It copies the
// pointers it changes, so the live configuration, which the API hands out by
// reference, is never modified.
func redactPolicy(p Policy) Policy {
	if p.ACL == nil || p.ACL.PasswordGate == nil || p.ACL.PasswordGate.PasswordHash == "" {
		return p
	}
	acl, gate := *p.ACL, *p.ACL.PasswordGate
	gate.PasswordHash = RedactedPlaceholder
	acl.PasswordGate = &gate
	p.ACL = &acl
	return p
}

// RedactPolicy returns a copy of p that is safe to show to API clients.
func RedactPolicy(p Policy) Policy { return redactPolicy(p) }

// RedactEndpoint returns a copy of e that is safe to show to API clients.
func RedactEndpoint(e Endpoint) Endpoint {
	e.Policy = redactPolicy(e.Policy)
	return e
}

// RedactSite returns a copy of s that is safe to show to API clients.
func RedactSite(s Site) Site {
	s.Policy = redactPolicy(s.Policy)
	if s.Endpoints != nil {
		eps := make([]Endpoint, len(s.Endpoints))
		for i, e := range s.Endpoints {
			eps[i] = RedactEndpoint(e)
		}
		s.Endpoints = eps
	}
	return s
}

// RedactSites returns redacted copies of sites (nil stays nil).
func RedactSites(sites []Site) []Site {
	if sites == nil {
		return nil
	}
	out := make([]Site, len(sites))
	for i, s := range sites {
		out[i] = RedactSite(s)
	}
	return out
}

// Redacted returns a copy of r that is safe to show to API clients. The
// original is not modified.
func (r *Root) Redacted() *Root {
	c := *r
	c.Global.Defaults = redactPolicy(r.Global.Defaults)
	c.Sites = RedactSites(r.Sites)
	return &c
}

func gateOf(p *Policy) *PasswordGate {
	if p == nil || p.ACL == nil {
		return nil
	}
	return p.ACL.PasswordGate
}

// restorePolicy fills a password-gate hash that the client left out or echoed
// back as the placeholder from the stored policy at the same position (old may
// be nil). A placeholder with nothing stored is cleared, so validation reports
// a missing hash instead of accepting the literal text.
func restorePolicy(p, old *Policy) {
	g := gateOf(p)
	if g == nil || (g.PasswordHash != "" && g.PasswordHash != RedactedPlaceholder) {
		return
	}
	if og := gateOf(old); og != nil && og.PasswordHash != "" {
		g.PasswordHash = og.PasswordHash
	} else {
		g.PasswordHash = ""
	}
}

// RestoreRedacted copies stored password-gate hashes from prev (which may be
// nil) into r wherever r omits the hash or carries RedactedPlaceholder.
// Positions are matched by site and endpoint id, so a hash can never move to a
// different site. r is modified in place and must not alias prev.
func (r *Root) RestoreRedacted(prev *Root) {
	var prevDefaults *Policy
	oldSites := map[string]*Site{}
	if prev != nil {
		prevDefaults = &prev.Global.Defaults
		for i := range prev.Sites {
			oldSites[prev.Sites[i].ID] = &prev.Sites[i]
		}
	}
	restorePolicy(&r.Global.Defaults, prevDefaults)
	for i := range r.Sites {
		var sitePolicy *Policy
		oldEndpoints := map[string]*Endpoint{}
		if ps := oldSites[r.Sites[i].ID]; ps != nil {
			sitePolicy = &ps.Policy
			for j := range ps.Endpoints {
				oldEndpoints[ps.Endpoints[j].ID] = &ps.Endpoints[j]
			}
		}
		restorePolicy(&r.Sites[i].Policy, sitePolicy)
		for j := range r.Sites[i].Endpoints {
			var endpointPolicy *Policy
			if pe := oldEndpoints[r.Sites[i].Endpoints[j].ID]; pe != nil {
				endpointPolicy = &pe.Policy
			}
			restorePolicy(&r.Sites[i].Endpoints[j].Policy, endpointPolicy)
		}
	}
}
