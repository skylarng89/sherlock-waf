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
)

// Options carries deployment settings that are not part of the user config.
type Options struct {
	HTTPPort  int    // default 80
	HTTPSPort int    // default 443
	DataDir   string // certificate storage; empty means Caddy's default
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
			if k := s.TLS.CertFile + "\x00" + s.TLS.KeyFile; !seenFile[k] {
				seenFile[k] = true
				files = append(files, obj{"certificate": s.TLS.CertFile, "key": s.TLS.KeyFile, "format": "pem"})
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
		"servers":    servers,
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
	chain := []obj{core}

	if eff.Mode != config.ModeOff && eff.WAF.Enabled {
		settings := waf.Settings{
			Mode:                  eff.Mode,
			ParanoiaLevel:         eff.WAF.ParanoiaLevel,
			BlockingParanoiaLevel: eff.WAF.BlockingParanoiaLevel,
			InboundThreshold:      eff.WAF.InboundThreshold,
			OutboundThreshold:     eff.WAF.OutboundThreshold,
			MaxBodyBytes:          eff.WAF.MaxBodyBytes,
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
			"skip_inspection_extensions": eff.WAF.SkipInspectionExtensions,
		}
		chain = append(chain, w)
	}

	if h := responseHeaders(s); h != nil {
		chain = append(chain, h)
	}
	return append(chain, reverseProxy(s.Upstreams)), nil
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

func reverseProxy(u config.Upstreams) obj {
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
		transport["tls"] = obj{"insecure_skip_verify": u.TLS.InsecureSkipVerify}
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
	return rp
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
