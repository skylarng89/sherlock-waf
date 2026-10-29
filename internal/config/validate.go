package config

import (
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// MaxEndpointsPerSite caps compiled subroutes per site (ADR-0012).
const MaxEndpointsPerSite = 500

const maxBodyBytesLimit int64 = 1 << 30

var (
	slugRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	validVerbs = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)

// Validate checks the (defaulted) configuration and returns every problem.
func (r *Root) Validate() Errors {
	var errs Errors
	if r.SchemaVersion != SchemaVersion {
		errs.add("/schema_version", CodeInvalid, "unsupported schema_version %d; this build supports %d", r.SchemaVersion, SchemaVersion)
	}
	r.Global.validate("/global", &errs)

	if len(r.Sites) == 0 {
		errs.add("/sites", CodeRequired, "at least one site is required")
	}
	ids := map[string]int{}
	type hostKey struct{ host, prefix string }
	hosts := map[hostKey]string{}
	for i := range r.Sites {
		s := &r.Sites[i]
		p := "/sites/" + strconv.Itoa(i)
		s.validate(p, r, &errs)
		if prev, dup := ids[s.ID]; dup && s.ID != "" {
			errs.add(p+"/id", CodeDuplicate, "site id %q already used by sites[%d]", s.ID, prev)
		}
		ids[s.ID] = i
		for j, h := range s.Hosts {
			k := hostKey{h, s.PathPrefix}
			if other, dup := hosts[k]; dup {
				errs.add(p+"/hosts/"+strconv.Itoa(j), CodeDuplicate, "host %q with path_prefix %q already served by site %q", h, s.PathPrefix, other)
			}
			hosts[k] = s.ID
		}
	}
	r.validateAccess(&errs)
	return errs
}

func (g *Global) validate(p string, errs *Errors) {
	if _, err := policy.ParseCIDRSet(g.TrustedProxies); err != nil {
		errs.add(p+"/trusted_proxies", CodeInvalid, "%v", err)
	}
	for i, h := range g.ClientIPHeaders {
		if !headerName.MatchString(h) {
			errs.add(p+"/client_ip_headers/"+strconv.Itoa(i), CodeInvalid, "%q is not a valid HTTP header name", h)
		}
	}
	if g.ACME.Email != "" && !strings.Contains(g.ACME.Email, "@") {
		errs.add(p+"/acme/email", CodeInvalid, "must be an email address")
	}
	if g.ACME.CA != "" {
		if u, err := url.Parse(g.ACME.CA); err != nil || u.Scheme != "https" || u.Host == "" {
			errs.add(p+"/acme/ca", CodeInvalid, "must be an https URL")
		}
	}
	g.Admin.validate(p+"/admin", errs)
	g.Events.validate(p+"/events", errs)
	g.Defaults.validate(p+"/defaults", errs)
}

func (a *Admin) validate(p string, errs *Errors) {
	if a.Listen != AdminOff {
		_, port, err := net.SplitHostPort(a.Listen)
		n, perr := strconv.Atoi(port)
		if err != nil || perr != nil || n < 0 || n > 65535 {
			errs.add(p+"/listen", CodeInvalid, "%q must be host:port or %q", a.Listen, AdminOff)
		}
	}
	if _, err := policy.ParseCIDRSet(a.AllowedCIDRs); err != nil {
		errs.add(p+"/allowed_cidrs", CodeInvalid, "%v", err)
	}
}

func (e *Events) validate(p string, errs *Errors) {
	if len(e.NodeName) > 128 || strings.ContainsAny(e.NodeName, "\r\n\t") {
		errs.add(p+"/node_name", CodeInvalid, "must be at most 128 characters without control characters")
	}
	if e.RetentionDays < 0 || e.RetentionDays > 3650 {
		errs.add(p+"/retention_days", CodeOutOfRange, "must be between 1 and 3650")
	}
	if r := e.AccessLog.SampleRate; r != nil && (*r < 0 || *r > 1) {
		errs.add(p+"/access_log/sample_rate", CodeOutOfRange, "must be between 0 and 1")
	}
	for i, pat := range e.Redaction.Patterns {
		if len(pat) > 256 {
			errs.add(p+"/redaction/patterns/"+strconv.Itoa(i), CodeInvalid, "longer than 256 bytes")
		} else if _, err := regexp.Compile(pat); err != nil {
			errs.add(p+"/redaction/patterns/"+strconv.Itoa(i), CodeInvalid, "invalid pattern: %v", err)
		}
	}
	if e.Sinks.FileMaxMB < 0 || e.Sinks.FileMaxMB > 10240 {
		errs.add(p+"/sinks/file_max_mb", CodeOutOfRange, "must be between 1 and 10240")
	}
	if e.Sinks.FileKeep < 0 || e.Sinks.FileKeep > 100 {
		errs.add(p+"/sinks/file_keep", CodeOutOfRange, "must be between 1 and 100")
	}
}

func (s *Site) validate(p string, r *Root, errs *Errors) {
	switch {
	case s.ID == "":
		errs.add(p+"/id", CodeRequired, "id is required")
	case !slugRE.MatchString(s.ID):
		errs.add(p+"/id", CodeInvalid, "id must be a lowercase slug (a-z, 0-9, '-', max 63 chars)")
	}
	if len(s.Hosts) == 0 {
		errs.add(p+"/hosts", CodeRequired, "at least one host is required")
	}
	seen := map[string]bool{}
	for i, h := range s.Hosts {
		hp := p + "/hosts/" + strconv.Itoa(i)
		if !validHost(h) {
			errs.add(hp, CodeInvalid, "%q is not a valid hostname (use lowercase DNS names, optionally with a leading \"*.\")", h)
		}
		if seen[h] {
			errs.add(hp, CodeDuplicate, "host %q listed twice", h)
		}
		seen[h] = true
	}
	if s.PathPrefix != "" && !validPath(s.PathPrefix) {
		errs.add(p+"/path_prefix", CodeInvalid, "must start with '/' and contain no '..' segments")
	}
	s.TLS.validate(p+"/tls", errs)
	s.Upstreams.validate(p+"/upstreams", errs)
	s.Policy.validate(p+"/policy", errs)
	s.validateEndpoints(p, errs)

	// Effective consistency is checked per resolved policy so inherited and
	// local values combine correctly.
	r.checkEffective(s, nil, p+"/policy", errs)
	for i := range s.Endpoints {
		r.checkEffective(s, &s.Endpoints[i], p+"/endpoints/"+strconv.Itoa(i)+"/policy", errs)
	}
}

func (r *Root) checkEffective(s *Site, ep *Endpoint, p string, errs *Errors) {
	eff := r.EffectivePolicy(s, ep)
	if eff.WAF.BlockingParanoiaLevel > eff.WAF.ParanoiaLevel {
		errs.add(p+"/waf/blocking_paranoia_level", CodeInvalid,
			"effective blocking_paranoia_level (%d) must not exceed paranoia_level (%d)",
			eff.WAF.BlockingParanoiaLevel, eff.WAF.ParanoiaLevel)
	}
}

func (t *TLS) validate(p string, errs *Errors) {
	switch t.Mode {
	case TLSACME, TLSNone:
		if t.CertFile != "" || t.KeyFile != "" || t.CertID != "" {
			errs.add(p, CodeInvalid, "cert_file, key_file and cert_id are only valid with mode \"file\"")
		}
	case TLSFile:
		switch {
		case t.CertID != "" && (t.CertFile != "" || t.KeyFile != ""):
			errs.add(p+"/cert_id", CodeInvalid, "use either cert_id or cert_file and key_file, not both")
		case t.CertID != "":
			if !validID(t.CertID) {
				errs.add(p+"/cert_id", CodeInvalid, "must be a certificate id")
			}
		default:
			if t.CertFile == "" {
				errs.add(p+"/cert_file", CodeRequired, "cert_file (with key_file) or cert_id is required with mode \"file\"")
			}
			if t.KeyFile == "" {
				errs.add(p+"/key_file", CodeRequired, "key_file (with cert_file) or cert_id is required with mode \"file\"")
			}
		}
	default:
		errs.add(p+"/mode", CodeInvalid, "must be one of acme, file, none")
	}
	if t.MinVersion != "1.2" && t.MinVersion != "1.3" {
		errs.add(p+"/min_version", CodeInvalid, "must be \"1.2\" or \"1.3\"")
	}
	if t.HSTS.MaxAge < 0 {
		errs.add(p+"/hsts/max_age", CodeOutOfRange, "must not be negative")
	}
}

func (u *Upstreams) validate(p string, errs *Errors) {
	if len(u.Targets) == 0 {
		errs.add(p+"/targets", CodeRequired, "at least one upstream target is required")
	}
	for i, t := range u.Targets {
		host, port, err := net.SplitHostPort(t)
		n, perr := strconv.Atoi(port)
		if err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			errs.add(p+"/targets/"+strconv.Itoa(i), CodeInvalid, "%q must be host:port", t)
		}
	}
	switch u.LBPolicy {
	case LBRoundRobin, LBLeastConn, LBIPHash:
	default:
		errs.add(p+"/lb_policy", CodeInvalid, "must be one of round_robin, least_conn, ip_hash")
	}
	if hc := u.HealthCheck; hc.Path != "" {
		if !validPath(hc.Path) {
			errs.add(p+"/health_check/path", CodeInvalid, "must start with '/'")
		}
		if hc.Interval <= 0 {
			errs.add(p+"/health_check/interval", CodeOutOfRange, "must be positive")
		}
		if hc.Timeout <= 0 || hc.Timeout > hc.Interval {
			errs.add(p+"/health_check/timeout", CodeOutOfRange, "must be positive and not exceed interval")
		}
	}
	if u.TLS.ClientCertID != "" {
		if !validID(u.TLS.ClientCertID) {
			errs.add(p+"/tls/client_cert_id", CodeInvalid, "must be a certificate id")
		}
		if !u.TLS.Enabled {
			errs.add(p+"/tls/client_cert_id", CodeInvalid, "a client certificate needs upstream tls to be enabled")
		}
	}
	switch u.HTTPVersion {
	case "", "1.1", "2":
	case "h2c":
		if u.TLS.Enabled {
			errs.add(p+"/http_version", CodeInvalid, "h2c is cleartext HTTP/2 and cannot be combined with upstream tls; use \"2\"")
		}
	default:
		errs.add(p+"/http_version", CodeInvalid, "must be one of 1.1, 2, h2c")
	}
	for name, d := range map[string]Duration{"dial": u.Timeouts.Dial, "read": u.Timeouts.Read, "write": u.Timeouts.Write} {
		if d < 0 {
			errs.add(p+"/timeouts/"+name, CodeOutOfRange, "must not be negative")
		}
	}
}

func (pol *Policy) validate(p string, errs *Errors) {
	if pol.Mode != nil && !slices.Contains([]Mode{ModeOff, ModeDetect, ModeBlock}, *pol.Mode) {
		errs.add(p+"/mode", CodeInvalid, "must be one of off, detect, block")
	}
	if pol.FailMode != nil && !slices.Contains([]FailMode{FailOpen, FailClosed}, *pol.FailMode) {
		errs.add(p+"/fail_mode", CodeInvalid, "must be one of open, closed")
	}
	if pol.BlockPage != nil && pol.BlockPage.TemplateID != nil && !validID(*pol.BlockPage.TemplateID) {
		errs.add(p+"/block_page/template_id", CodeInvalid, "must be %q or the id of an uploaded block page", DefaultBlockPageTemplate)
	}
	w := pol.WAF
	if w == nil {
		return
	}
	wp := p + "/waf"
	if w.ParanoiaLevel != nil && (*w.ParanoiaLevel < 1 || *w.ParanoiaLevel > 4) {
		errs.add(wp+"/paranoia_level", CodeOutOfRange, "must be between 1 and 4")
	}
	if w.BlockingParanoiaLevel != nil && (*w.BlockingParanoiaLevel < 1 || *w.BlockingParanoiaLevel > 4) {
		errs.add(wp+"/blocking_paranoia_level", CodeOutOfRange, "must be between 1 and 4")
	}
	if w.InboundThreshold != nil && *w.InboundThreshold < 1 {
		errs.add(wp+"/inbound_threshold", CodeOutOfRange, "must be at least 1")
	}
	if w.OutboundThreshold != nil && *w.OutboundThreshold < 1 {
		errs.add(wp+"/outbound_threshold", CodeOutOfRange, "must be at least 1")
	}
	if w.OutboundInspection != nil && *w.OutboundInspection {
		errs.add(wp+"/outbound_inspection", CodeUnsupported, "response inspection is not implemented yet")
	}
	if w.MaxBodyBytes != nil && (*w.MaxBodyBytes < 1 || *w.MaxBodyBytes > maxBodyBytesLimit) {
		errs.add(wp+"/max_body_bytes", CodeOutOfRange, "must be between 1 and %d", maxBodyBytesLimit)
	}
	for i, e := range w.SkipInspectionExtensions {
		if len(e) < 2 || e[0] != '.' || strings.ContainsAny(e, "/\\ ") {
			errs.add(wp+"/skip_inspection_extensions/"+strconv.Itoa(i), CodeInvalid, "%q must look like \".css\"", e)
		}
	}
}

func (s *Site) validateEndpoints(p string, errs *Errors) {
	if len(s.Endpoints) > MaxEndpointsPerSite {
		errs.add(p+"/endpoints", CodeOutOfRange, "at most %d endpoints per site", MaxEndpointsPerSite)
		return
	}
	ids := map[string]int{}
	valid := make([]bool, len(s.Endpoints))
	for i := range s.Endpoints {
		e := &s.Endpoints[i]
		ep := p + "/endpoints/" + strconv.Itoa(i)
		before := len(*errs)
		switch {
		case e.ID == "":
			errs.add(ep+"/id", CodeRequired, "id is required")
		case !slugRE.MatchString(e.ID):
			errs.add(ep+"/id", CodeInvalid, "id must be a lowercase slug")
		}
		if prev, dup := ids[e.ID]; dup && e.ID != "" {
			errs.add(ep+"/id", CodeDuplicate, "endpoint id %q already used by endpoints[%d]", e.ID, prev)
		}
		ids[e.ID] = i
		e.Match.validate(ep+"/match", errs)
		e.Policy.validate(ep+"/policy", errs)
		valid[i] = len(*errs) == before
	}
	for i := range s.Endpoints {
		for j := i + 1; j < len(s.Endpoints); j++ {
			if valid[i] && valid[j] && s.Endpoints[i].Match.ambiguousWith(s.Endpoints[j].Match) {
				errs.add(p+"/endpoints/"+strconv.Itoa(j)+"/match", CodeAmbiguous,
					"endpoints %q and %q have equal precedence and can match the same request", s.Endpoints[i].ID, s.Endpoints[j].ID)
			}
		}
	}
}

func (m *EndpointMatch) validate(p string, errs *Errors) {
	set := 0
	for _, v := range []string{m.Path, m.PathPrefix, m.PathGlob} {
		if v != "" {
			set++
		}
	}
	if set != 1 {
		errs.add(p, CodeInvalid, "exactly one of path, path_prefix or path_glob is required")
		return
	}
	switch {
	case m.Path != "" && !validPath(m.Path):
		errs.add(p+"/path", CodeInvalid, "must start with '/' and contain no '..' segments")
	case m.PathPrefix != "" && !validPath(m.PathPrefix):
		errs.add(p+"/path_prefix", CodeInvalid, "must start with '/' and contain no '..' segments")
	case m.PathGlob != "":
		if !validPath(m.PathGlob) {
			errs.add(p+"/path_glob", CodeInvalid, "must start with '/' and contain no '..' segments")
		} else if _, err := path.Match(m.PathGlob, ""); err != nil {
			errs.add(p+"/path_glob", CodeInvalid, "invalid glob: %v", err)
		}
	}
	seen := map[string]bool{}
	for i, v := range m.Methods {
		if !slices.Contains(validVerbs, v) {
			errs.add(p+"/methods/"+strconv.Itoa(i), CodeInvalid, "%q must be an upper-case HTTP method", v)
		}
		if seen[v] {
			errs.add(p+"/methods/"+strconv.Itoa(i), CodeDuplicate, "method %q listed twice", v)
		}
		seen[v] = true
	}
}

func validPath(s string) bool {
	return strings.HasPrefix(s, "/") && !slices.Contains(strings.Split(s, "/"), "..") && !strings.ContainsAny(s, "\x00 ")
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	h = strings.TrimPrefix(h, "*.")
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for l := range strings.SplitSeq(h, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// validID matches the slug form used for stored objects (block pages, uploaded
// certificate ids are ULIDs, which also match).
func validID(s string) bool { return idPattern.MatchString(s) }

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
