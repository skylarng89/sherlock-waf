// Package compiler turns a validated config.Root into Caddy JSON. The output
// is deterministic (same input, same bytes) so it can be golden-tested and
// diffed. All policy merging happens here, once: every endpoint becomes its
// own subroute carrying its effective policy, so nothing is merged per request.
package compiler

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/waf"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
)

// Options carries deployment settings that are not part of the user config.
type Options struct {
	HTTPPort  int    // default 80
	HTTPSPort int    // default 443
	DataDir   string // certificate storage; empty means Caddy's default
	// CertFiles resolves an uploaded certificate id to PEM files on disk, which
	// Caddy loads. Nil means no uploaded certificates are available and a
	// config that references one fails to compile.
	CertFiles func(id string) (certFile, keyFile string, err error)
}

type obj = map[string]any

const (
	httpServer  = "sherlock_http"
	httpsServer = "sherlock_https"
)

// Compile renders root as indented Caddy JSON.
func Compile(root *config.Root, opts Options) ([]byte, error) {
	if root == nil {
		return nil, errors.New("compiling config: nil root")
	}
	if opts.HTTPPort == 0 {
		opts.HTTPPort = 80
	}
	if opts.HTTPSPort == 0 {
		opts.HTTPSPort = 443
	}
	c := compilation{root: root, opts: opts}
	cfg, err := c.build()
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding caddy config: %w", err)
	}
	return append(out, '\n'), nil
}

type compilation struct {
	root *config.Root
	opts Options
}

func (c *compilation) resolveCert(id string) (certFile, keyFile string, err error) {
	if c.opts.CertFiles == nil {
		return "", "", fmt.Errorf("certificate %q is not available on this node", id)
	}
	certFile, keyFile, err = c.opts.CertFiles(id)
	if err != nil {
		return "", "", fmt.Errorf("certificate %q: %w", id, err)
	}
	return certFile, keyFile, nil
}

func (c *compilation) build() (obj, error) {
	sites := orderSites(c.root.Sites)

	var httpRoutes, httpsRoutes []obj
	var tlsHosts, acmeHosts, fileHosts []string
	var files []obj
	seenFile := map[string]bool{}
	var policies []obj

	for _, s := range sites {
		route, err := c.siteRoute(s)
		if err != nil {
			return nil, fmt.Errorf("site %q: %w", s.ID, err)
		}
		if s.TLS.Mode == config.TLSNone {
			httpRoutes = append(httpRoutes, route)
			continue
		}
		httpsRoutes = append(httpsRoutes, route)
		tlsHosts = append(tlsHosts, s.Hosts...)
		switch s.TLS.Mode {
		case config.TLSFile:
			fileHosts = append(fileHosts, s.Hosts...)
			certFile, keyFile := s.TLS.CertFile, s.TLS.KeyFile
			if s.TLS.CertID != "" {
				var err error
				if certFile, keyFile, err = c.resolveCert(s.TLS.CertID); err != nil {
					return nil, fmt.Errorf("site %q: %w", s.ID, err)
				}
			}
			if k := certFile + "\x00" + keyFile; !seenFile[k] {
				seenFile[k] = true
				files = append(files, obj{"certificate": certFile, "key": keyFile, "format": "pem"})
			}
		case config.TLSACME:
			acmeHosts = append(acmeHosts, s.Hosts...)
		case config.TLSNone:
		}
		policies = append(policies, connPolicy(s))
	}

	servers := obj{}
	clientIP := c.clientIPSettings()

	// HTTP server: plain sites, redirects for TLS sites, 421 for the rest.
	redirect := c.redirectRoute(tlsHosts)
	routes := slices.Concat(httpRoutes, redirect, []obj{unknownHostRoute()})
	servers[httpServer] = merge(obj{
		"listen":          []string{":" + strconv.Itoa(c.opts.HTTPPort)},
		"routes":          routes,
		"automatic_https": obj{"disable_redirects": true},
	}, clientIP)

	apps := obj{}
	if len(httpsRoutes) > 0 {
		policies = append(policies, obj{"protocol_min": "tls1.2"})
		auto := obj{"disable_redirects": true}
		if len(fileHosts) > 0 {
			auto["skip_certificates"] = unique(fileHosts)
		}
		servers[httpsServer] = merge(obj{
			"listen":                  []string{":" + strconv.Itoa(c.opts.HTTPSPort)},
			"routes":                  append(httpsRoutes, unknownHostRoute()),
			"tls_connection_policies": policies,
			"automatic_https":         auto,
		}, clientIP)

		tlsApp := obj{}
		if len(files) > 0 {
			tlsApp["certificates"] = obj{"load_files": files}
		}
		if p := c.acmePolicy(unique(acmeHosts)); p != nil {
			tlsApp["automation"] = obj{"policies": []obj{p}}
		}
		if len(tlsApp) > 0 {
			apps["tls"] = tlsApp
		}
	}
	apps["http"] = obj{
		"http_port":  c.opts.HTTPPort,
		"https_port": c.opts.HTTPSPort,
		// A reload stops the old servers gracefully; without a bound, a
		// long-lived connection could hold the reload up indefinitely.
		"grace_period": "10s",
		"servers":      servers,
	}

	cfg := obj{
		// The YAML file is the source of truth; never autosave Caddy's copy.
		"admin": obj{"disabled": true, "config": obj{"persist": false}},
		"apps":  apps,
	}
	if c.opts.DataDir != "" {
		cfg["storage"] = obj{"module": "file_system", "root": c.opts.DataDir}
	}
	return cfg, nil
}

// clientIPSettings keeps Caddy's {client_ip} in agreement with sherlock_core.
func (c *compilation) clientIPSettings() obj {
	g := c.root.Global
	if len(g.TrustedProxies) == 0 {
		return obj{}
	}
	return obj{
		"trusted_proxies":        obj{"source": "static", "ranges": g.TrustedProxies},
		"client_ip_headers":      g.ClientIPHeaders,
		"trusted_proxies_strict": 1,
	}
}

func (c *compilation) acmePolicy(hosts []string) obj {
	a := c.root.Global.ACME
	if len(hosts) == 0 || (a.Email == "" && a.CA == "") {
		return nil
	}
	issuer := obj{"module": "acme"}
	if a.Email != "" {
		issuer["email"] = a.Email
	}
	if a.CA != "" {
		issuer["ca"] = a.CA
	}
	return obj{"subjects": hosts, "issuers": []obj{issuer}}
}

func (c *compilation) redirectRoute(hosts []string) []obj {
	hosts = unique(hosts)
	if len(hosts) == 0 {
		return nil
	}
	target := "https://{http.request.host}"
	if c.opts.HTTPSPort != 443 {
		target += ":" + strconv.Itoa(c.opts.HTTPSPort)
	}
	target += "{http.request.uri}"
	return []obj{{
		"match": []obj{{"host": hosts}},
		"handle": []obj{{
			"handler":     "static_response",
			"status_code": 308,
			"headers":     obj{"Location": []string{target}},
		}},
		"terminal": true,
	}}
}

func unknownHostRoute() obj {
	return obj{
		"handle": []obj{{
			"handler":     "static_response",
			"status_code": 421,
			"body":        "421 Misdirected Request\n",
			"headers":     obj{"Content-Type": []string{"text/plain; charset=utf-8"}},
		}},
		"terminal": true,
	}
}

func connPolicy(s config.Site) obj {
	p := obj{"match": obj{"sni": s.Hosts}}
	if s.TLS.MinVersion == "1.3" {
		p["protocol_min"] = "tls1.3"
	} else {
		p["protocol_min"] = "tls1.2"
	}
	return p
}

// siteRoute builds the route for one site: a subroute per endpoint in
// precedence order, then the site-default subroute.
func (c *compilation) siteRoute(s config.Site) (obj, error) {
	var inner []obj
	for _, ep := range s.OrderedEndpoints() {
		eff := c.root.EffectivePolicy(&s, &ep)
		chain, err := c.chain(s, eff)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", ep.ID, err)
		}
		inner = append(inner, obj{
			"match":    []obj{endpointMatcher(ep.Match)},
			"handle":   chain,
			"terminal": true,
		})
	}
	chain, err := c.chain(s, c.root.EffectivePolicy(&s, nil))
	if err != nil {
		return nil, err
	}
	inner = append(inner, obj{"handle": chain, "terminal": true})

	matcher := obj{"host": s.Hosts}
	if s.PathPrefix != "" {
		matcher["path"] = prefixPatterns(s.PathPrefix)
	}
	return obj{
		"match":    []obj{matcher},
		"handle":   []obj{{"handler": "subroute", "routes": inner}},
		"terminal": true,
	}, nil
}

func endpointMatcher(m config.EndpointMatch) obj {
	out := obj{}
	switch {
	case m.Path != "":
		out["path"] = []string{m.Path}
	case m.PathPrefix != "":
		out["path"] = prefixPatterns(m.PathPrefix)
	default:
		out["path"] = []string{m.PathGlob}
	}
	if len(m.Methods) > 0 {
		out["method"] = slices.Sorted(slices.Values(m.Methods))
	}
	return out
}

// prefixPatterns matches the prefix itself and anything below it by path
// segment, so "/app" does not capture "/apple".
func prefixPatterns(prefix string) []string {
	if strings.HasSuffix(prefix, "/") {
		return []string{prefix + "*"}
	}
	return []string{prefix, prefix + "/*"}
}

// chain is the fixed handler order from request-pipeline.md: core, waf, then
// response headers and the reverse proxy. It is not user-configurable.
func (c *compilation) chain(s config.Site, eff config.EffectivePolicy) ([]obj, error) {
	g := c.root.Global
	core := obj{
		"handler":   "sherlock_core",
		"site_id":   s.ID,
		"mode":      string(eff.Mode),
		"fail_mode": string(eff.FailMode),
	}
	if len(g.TrustedProxies) > 0 {
		core["trusted_proxies"] = g.TrustedProxies
		core["client_ip_headers"] = g.ClientIPHeaders
	}
	if ws := s.Upstreams.WebSockets; ws != nil && !*ws {
		core["block_websockets"] = true
	}
	chain := []obj{core}
	if acl := c.aclHandler(s.ID, eff); acl != nil {
		chain = append(chain, acl)
	}
	// Auto-ban is a per-site setting: it always comes from the site-level policy,
	// so every route of the site registers the same values.
	siteEff := c.root.EffectivePolicy(&s, nil)
	if rl := rateLimitHandler(s.ID, eff, siteEff.AutoBan); rl != nil {
		chain = append(chain, rl)
	}
	if bot := botHandler(s.ID, eff.Bot); bot != nil {
		chain = append(chain, bot)
	}

	if eff.Mode != config.ModeOff && eff.WAF.Enabled {
		patches, err := vpatch.Select(eff.VirtualPatches.Enabled, eff.VirtualPatches.Disabled, eff.DeclaredStacks())
		if err != nil {
			return nil, err
		}
		settings := waf.Settings{
			Mode:                  eff.Mode,
			ParanoiaLevel:         eff.WAF.ParanoiaLevel,
			BlockingParanoiaLevel: eff.WAF.BlockingParanoiaLevel,
			InboundThreshold:      eff.WAF.InboundThreshold,
			OutboundThreshold:     eff.WAF.OutboundThreshold,
			MaxBodyBytes:          eff.WAF.MaxBodyBytes,
			Exclusions:            eff.WAF.Exclusions,
			CustomRules:           eff.WAF.CustomRules,
			VirtualPatches:        patches,
		}
		if eff.WAF.OutboundInspection {
			settings.OutboundInspection = true
			settings.OutboundMaxBodyBytes = eff.WAF.OutboundMaxBodyBytes
			settings.OutboundContentTypes = eff.WAF.OutboundContentTypes
		}
		if _, err := settings.Directives(); err != nil {
			return nil, err
		}
		w := obj{
			"handler":                    "sherlock_waf",
			"site_id":                    s.ID,
			"fail_mode":                  string(eff.FailMode),
			"mode":                       string(settings.Mode),
			"paranoia_level":             settings.ParanoiaLevel,
			"blocking_paranoia_level":    settings.BlockingParanoiaLevel,
			"inbound_threshold":          settings.InboundThreshold,
			"outbound_threshold":         settings.OutboundThreshold,
			"max_body_bytes":             settings.MaxBodyBytes,
			"skip_inspection_extensions": skipExtensions(eff, patches),
		}
		if len(settings.Exclusions) > 0 {
			w["exclusions"] = settings.Exclusions
		}
		if settings.CustomRules != "" {
			w["custom_rules"] = settings.CustomRules
		}
		if len(settings.VirtualPatches) > 0 {
			w["virtual_patches"] = settings.VirtualPatches
		}
		if settings.OutboundInspection {
			w["outbound_inspection"] = true
			w["outbound_max_body_bytes"] = settings.OutboundMaxBodyBytes
			w["outbound_content_types"] = settings.OutboundContentTypes
		}
		if id := eff.BlockPage.TemplateID; id != config.DefaultBlockPageTemplate {
			w["block_page_id"] = id
		}
		chain = append(chain, w)
	}

	if h := responseHeaders(s); h != nil {
		chain = append(chain, h)
	}
	rp, err := c.reverseProxy(s.Upstreams)
	if err != nil {
		return nil, err
	}
	return append(chain, rp), nil
}

func responseHeaders(s config.Site) obj {
	if s.Headers.SecurityHeaders == nil || !*s.Headers.SecurityHeaders {
		return nil
	}
	set := obj{
		"X-Content-Type-Options": []string{"nosniff"},
		"Referrer-Policy":        []string{"strict-origin-when-cross-origin"},
	}
	if s.TLS.Mode != config.TLSNone && s.TLS.HSTS.Enabled != nil && *s.TLS.HSTS.Enabled {
		v := "max-age=" + strconv.Itoa(s.TLS.HSTS.MaxAge)
		if s.TLS.HSTS.IncludeSubdomains {
			v += "; includeSubDomains"
		}
		set["Strict-Transport-Security"] = []string{v}
	}
	return obj{
		"handler":  "headers",
		"response": obj{"set": set, "deferred": true},
	}
}

func (c *compilation) reverseProxy(u config.Upstreams) (obj, error) {
	upstreams := make([]obj, len(u.Targets))
	for i, t := range u.Targets {
		upstreams[i] = obj{"dial": t}
	}
	transport := obj{
		"protocol":      "http",
		"dial_timeout":  dur(u.Timeouts.Dial),
		"read_timeout":  dur(u.Timeouts.Read),
		"write_timeout": dur(u.Timeouts.Write),
	}
	if u.TLS.Enabled {
		t := obj{"insecure_skip_verify": u.TLS.InsecureSkipVerify}
		if id := u.TLS.ClientCertID; id != "" {
			certFile, keyFile, err := c.resolveCert(id)
			if err != nil {
				return nil, fmt.Errorf("upstream client %w", err)
			}
			t["client_certificate_file"] = certFile
			t["client_certificate_key_file"] = keyFile
		}
		transport["tls"] = t
	}
	if u.HTTPVersion != "" {
		transport["versions"] = []string{u.HTTPVersion}
	}
	rp := obj{
		"handler":        "reverse_proxy",
		"upstreams":      upstreams,
		"load_balancing": obj{"selection_policy": obj{"policy": string(u.LBPolicy)}},
		"transport":      transport,
	}
	if hc := u.HealthCheck; hc.Path != "" {
		rp["health_checks"] = obj{"active": obj{
			"uri": hc.Path, "interval": dur(hc.Interval), "timeout": dur(hc.Timeout),
		}}
	}
	return rp, nil
}

func dur(d config.Duration) string { return d.Std().Round(time.Millisecond).String() }

// orderSites puts path-scoped sites first (longest prefix first) and
// wildcard-host sites last so the most specific route wins; ties keep
// declaration order.
func orderSites(in []config.Site) []config.Site {
	out := slices.Clone(in)
	wildcard := func(s config.Site) bool {
		return slices.ContainsFunc(s.Hosts, func(h string) bool { return strings.HasPrefix(h, "*.") })
	}
	sort.SliceStable(out, func(i, j int) bool {
		if wi, wj := wildcard(out[i]), wildcard(out[j]); wi != wj {
			return !wi
		}
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func merge(a, b obj) obj {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// aclHandler emits sherlock_acl, or nil when the policy asks for nothing.
func (c *compilation) aclHandler(siteID string, eff config.EffectivePolicy) obj {
	a := eff.ACL
	countries := a.CountryMode != config.CountryOff && (a.CountryMode == config.CountryAllow || len(a.Countries) > 0)
	if len(a.AllowLists) == 0 && len(a.DenyLists) == 0 && !countries && !a.Reputation && !a.PasswordGate && !a.AllowBypassWAF {
		// Temporary bans still apply to every site, so the module is always present.
		return obj{"handler": "sherlock_acl", "site_id": siteID}
	}
	h := obj{"handler": "sherlock_acl", "site_id": siteID}
	if len(a.AllowLists) > 0 {
		h["allow_lists"] = a.AllowLists
	}
	if len(a.DenyLists) > 0 {
		h["deny_lists"] = a.DenyLists
	}
	if countries {
		h["country_mode"] = a.CountryMode
		h["countries"] = a.Countries
	}
	if a.Reputation {
		h["reputation"] = true
		h["reputation_action"] = a.ReputationAct
	}
	if a.PasswordGate {
		h["gate_username"] = a.GateUsername
		h["gate_hash"] = a.GateHash
	}
	if a.AllowBypassWAF {
		h["allow_bypass_waf"] = true
	}
	return h
}

// rateLimitHandler emits sherlock_ratelimit, or nil without limits or auto-ban.
func rateLimitHandler(siteID string, eff config.EffectivePolicy, ab config.EffectiveAutoBan) obj {
	if len(eff.RateLimits) == 0 && !ab.Enabled {
		return nil
	}
	h := obj{"handler": "sherlock_ratelimit", "site_id": siteID}
	if eff.Bot.Enabled {
		h["challenge_handoff"] = true // rate limits with action challenge hand over to the bot module
	}
	if len(eff.RateLimits) > 0 {
		rules := make([]obj, len(eff.RateLimits))
		for i, r := range eff.RateLimits {
			rule := obj{"name": r.Name, "key": r.Key, "limit": r.Limit, "window": dur(r.Window), "action": r.Action}
			if len(r.Match.Paths) > 0 {
				rule["paths"] = r.Match.Paths
			}
			if len(r.Match.Methods) > 0 {
				rule["methods"] = r.Match.Methods
			}
			rules[i] = rule
		}
		h["rules"] = rules
	}
	if ab.Enabled {
		h["auto_ban"] = obj{
			"blocks_threshold": ab.BlocksThreshold,
			"window":           ab.Window.String(),
			"ban_duration":     ab.BanDuration.String(),
		}
	}
	return h
}

// botHandler emits sherlock_bot, or nil while bot defence is off.
func botHandler(siteID string, b config.EffectiveBot) obj {
	if !b.Enabled {
		return nil
	}
	h := obj{
		"handler": "sherlock_bot", "site_id": siteID, "challenge": b.Challenge, "difficulty": b.Difficulty,
		"clearance_ttl": b.ClearanceTTL.String(), "verified_bots": b.VerifiedBots,
	}
	if b.SiteKey != "" {
		h["site_key"] = b.SiteKey
	}
	if len(b.Rules) > 0 {
		rules := make([]obj, len(b.Rules))
		for i, r := range b.Rules {
			rule := obj{"action": r.Action}
			if len(r.Match.Paths) > 0 {
				rule["paths"] = r.Match.Paths
			}
			if len(r.Match.Methods) > 0 {
				rule["methods"] = r.Match.Methods
			}
			if len(r.Match.Countries) > 0 {
				rule["countries"] = r.Match.Countries
			}
			if r.Match.Reputation != nil && *r.Match.Reputation {
				rule["reputation"] = true
			}
			rules[i] = rule
		}
		h["rules"] = rules
	}
	return h
}

// skipExtensions returns the static-asset extensions that bypass inspection.
// A site that declares a product stack with active virtual patches inspects
// everything: exploits such as ProxyLogon ride on innocuous-looking asset paths
// with the payload in a cookie, which the skip would otherwise hide from the patch.
func skipExtensions(eff config.EffectivePolicy, patches []string) []string {
	if len(patches) > 0 && len(eff.DeclaredStacks()) > 0 {
		return nil
	}
	return eff.WAF.SkipInspectionExtensions
}
