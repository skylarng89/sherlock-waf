// Package metrics holds Sherlock's Prometheus series. They live in a private
// registry so Caddy's own collectors never leak into /metrics unannounced.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// Registry is served on the admin listener at /metrics.
var Registry = prometheus.NewRegistry()

var (
	apiThrottled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_api_throttled_total",
		Help: "Control-plane requests refused with 429 by the request limiter, by scope (principal or anonymous).",
	}, []string{"scope"})
	loginFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_login_failures_total",
		Help: "Failed logins observed on declared login endpoints, by site.",
	}, []string{"site"})
	loginActions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_login_actions_total",
		Help: "Login-protection decisions, by site, action (challenge, block, log) and the scope that tripped (ip, username, device).",
	}, []string{"site", "action", "scope"})
	dlpMatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_dlp_matches_total",
		Help: "Sensitive values found in responses, by site, detector (pan, iban, custom) and action (mask, block, log). The values themselves are never recorded.",
	}, []string{"site", "detector", "action"})
	dlpSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_dlp_skipped_total",
		Help: "Responses the data-protection scanner passed through unscanned, by site and reason (too_large, encoding, content_type_unknown).",
	}, []string{"site", "reason"})
	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sherlock_requests_total",
		Help: "Requests with a security decision, by site and action. Clean requests count as action=allow.",
	}, []string{"site", "action"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sherlock_request_duration_seconds",
		Help:    "Time from request start to response completion as seen by sherlock_core, by site.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"site"})

	wafDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sherlock_waf_duration_seconds",
		Help:    "Time spent inside the WAF inspection stage, by site.",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
	}, []string{"site"})

	configVersion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sherlock_config_version_info",
		Help: "Always 1; the version label identifies the active configuration (hash of the compiled config).",
	}, []string{"version"})

	crsVersion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sherlock_crs_version_info",
		Help: "Always 1; the version label is the embedded OWASP CRS release.",
	}, []string{"version"})
)

func init() {
	Registry.MustRegister(requests, requestDuration, wafDuration, configVersion, crsVersion, apiThrottled,
		loginFailures, loginActions, dlpMatches, dlpSkipped,
		internalErrorCollector{src: policy.InternalErrors.Load},
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sherlock_requests_in_flight",
			Help: "Requests currently inside sherlock_core, until their event is published.",
		}, func() float64 { return float64(policy.InFlight.Load()) }),
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// ObserveAPIThrottled counts one control-plane request refused by the request limiter.
func ObserveAPIThrottled(scope string) { apiThrottled.WithLabelValues(scope).Inc() }

// ObserveLoginFailure counts one failed login seen on a declared endpoint.
func ObserveLoginFailure(site string) { loginFailures.WithLabelValues(site).Inc() }

// ObserveLoginAction counts one login-protection decision.
func ObserveLoginAction(site, action, scope string) {
	loginActions.WithLabelValues(site, action, scope).Inc()
}

// ObserveDLPMatches counts n sensitive values found in one response. detector
// must be pan, iban or custom (never a user-defined name, which is unbounded).
func ObserveDLPMatches(site, detector, action string, n int) {
	dlpMatches.WithLabelValues(site, detector, action).Add(float64(n))
}

// ObserveDLPSkipped counts one response passed through unscanned.
func ObserveDLPSkipped(site, reason string) { dlpSkipped.WithLabelValues(site, reason).Inc() }

// ObserveRequest records one finished request. It is called on the request
// path, so it only touches pre-created collectors.
func ObserveRequest(site, action string, total, waf time.Duration) {
	requests.WithLabelValues(site, action).Inc()
	requestDuration.WithLabelValues(site).Observe(total.Seconds())
	if waf > 0 {
		wafDuration.WithLabelValues(site).Observe(waf.Seconds())
	}
}

// SetConfigVersion publishes the active config version, replacing the old one.
func SetConfigVersion(version string) {
	configVersion.Reset()
	configVersion.WithLabelValues(version).Set(1)
}

// SetCRSVersion publishes the embedded CRS version.
func SetCRSVersion(version string) {
	crsVersion.Reset()
	crsVersion.WithLabelValues(version).Set(1)
}

// RegisterEventCounters exposes the event bus counters (published, dropped) as
// counters read at scrape time, so nothing is added to the request path.
// stats must be safe for concurrent use. It replaces any earlier registration.
func RegisterEventCounters(stats func() (published, dropped uint64)) {
	Registry.Unregister(eventCollector{})
	Registry.MustRegister(eventCollector{stats: stats})
}

var (
	publishedDesc = prometheus.NewDesc("sherlock_events_published_total", "Security and access events accepted by the event bus.", nil, nil)
	droppedDesc   = prometheus.NewDesc("sherlock_events_dropped_total", "Events overwritten in the bounded ring before every consumer read them.", nil, nil)
	internalDesc  = prometheus.NewDesc("sherlock_internal_errors_total", "Recovered internal failures in data plane modules.", nil, nil)
)

type eventCollector struct{ stats func() (uint64, uint64) }

func (eventCollector) Describe(ch chan<- *prometheus.Desc) { ch <- publishedDesc; ch <- droppedDesc }

func (c eventCollector) Collect(ch chan<- prometheus.Metric) {
	if c.stats == nil {
		return
	}
	p, d := c.stats()
	ch <- prometheus.MustNewConstMetric(publishedDesc, prometheus.CounterValue, float64(p))
	ch <- prometheus.MustNewConstMetric(droppedDesc, prometheus.CounterValue, float64(d))
}

type internalErrorCollector struct{ src func() uint64 }

func (internalErrorCollector) Describe(ch chan<- *prometheus.Desc) { ch <- internalDesc }

func (c internalErrorCollector) Collect(ch chan<- prometheus.Metric) {
	if c.src != nil {
		ch <- prometheus.MustNewConstMetric(internalDesc, prometheus.CounterValue, float64(c.src()))
	}
}

// UpstreamStatus is one origin's health as last probed by the server.
type UpstreamStatus struct {
	Site     string
	Upstream string
	Healthy  bool
}

// CertExpiry is the expiry of the certificate that serves a site host.
type CertExpiry struct {
	Site     string
	Host     string
	NotAfter time.Time
}

// RegisterUpstreamHealth exposes sherlock_upstream_healthy from src, which is
// called at scrape time and must return a snapshot without doing I/O. It
// replaces any earlier registration.
func RegisterUpstreamHealth(src func() []UpstreamStatus) {
	Registry.Unregister(upstreamCollector{})
	Registry.MustRegister(upstreamCollector{src: src})
}

// RegisterCertExpiry exposes sherlock_cert_expiry_seconds from src, which is
// called at scrape time and must return a snapshot without doing I/O. It
// replaces any earlier registration.
func RegisterCertExpiry(src func() []CertExpiry) {
	Registry.Unregister(certExpiryCollector{})
	Registry.MustRegister(certExpiryCollector{src: src, now: time.Now})
}

var (
	upstreamDesc = prometheus.NewDesc("sherlock_upstream_healthy", "1 when the last health probe of the upstream succeeded, 0 when it failed.", []string{"site", "upstream"}, nil)
	certDesc     = prometheus.NewDesc("sherlock_cert_expiry_seconds", "Seconds until the certificate serving the host expires; negative once it has expired.", []string{"site", "host"}, nil)
)

type upstreamCollector struct{ src func() []UpstreamStatus }

func (upstreamCollector) Describe(ch chan<- *prometheus.Desc) { ch <- upstreamDesc }

func (c upstreamCollector) Collect(ch chan<- prometheus.Metric) {
	if c.src == nil {
		return
	}
	for _, u := range c.src() {
		v := 0.0
		if u.Healthy {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(upstreamDesc, prometheus.GaugeValue, v, u.Site, u.Upstream)
	}
}

type certExpiryCollector struct {
	src func() []CertExpiry
	now func() time.Time
}

func (certExpiryCollector) Describe(ch chan<- *prometheus.Desc) { ch <- certDesc }

func (c certExpiryCollector) Collect(ch chan<- prometheus.Metric) {
	if c.src == nil {
		return
	}
	now := c.now()
	for _, e := range c.src() {
		ch <- prometheus.MustNewConstMetric(certDesc, prometheus.GaugeValue, e.NotAfter.Sub(now).Seconds(), e.Site, e.Host)
	}
}
