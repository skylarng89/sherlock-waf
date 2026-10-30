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
	Registry.MustRegister(requests, requestDuration, wafDuration, configVersion, crsVersion,
		internalErrorCollector{src: policy.InternalErrors.Load},
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sherlock_requests_in_flight",
			Help: "Requests currently inside sherlock_core, until their event is published.",
		}, func() float64 { return float64(policy.InFlight.Load()) }),
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

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
