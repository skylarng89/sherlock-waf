package metrics

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// samples gathers name from reg and returns each series as `label=value,...`
// mapped to its gauge value. It reads exposition data through the Gather API,
// so tests need no extra modules.
func samples(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	fams, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		require.Equal(t, "GAUGE", f.GetType().String(), "series must be a gauge")
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			slices.Sort(labels)
			out[strings.Join(labels, ",")] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestUpstreamHealthExposesOneGaugePerUpstream(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(upstreamCollector{src: func() []UpstreamStatus {
		return []UpstreamStatus{
			{Site: "shop", Upstream: "10.0.0.1:8080", Healthy: true},
			{Site: "shop", Upstream: "10.0.0.2:8080", Healthy: false},
		}
	}}))

	assert.Equal(t, map[string]float64{
		"site=shop,upstream=10.0.0.1:8080": 1,
		"site=shop,upstream=10.0.0.2:8080": 0,
	}, samples(t, reg, "sherlock_upstream_healthy"))
}

func TestUpstreamHealthReflectsTheSourceAtEachScrape(t *testing.T) {
	healthy := true
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(upstreamCollector{src: func() []UpstreamStatus {
		return []UpstreamStatus{{Site: "shop", Upstream: "10.0.0.1:8080", Healthy: healthy}}
	}}))

	assert.Equal(t, 1.0, samples(t, reg, "sherlock_upstream_healthy")["site=shop,upstream=10.0.0.1:8080"])
	healthy = false
	assert.Equal(t, 0.0, samples(t, reg, "sherlock_upstream_healthy")["site=shop,upstream=10.0.0.1:8080"])
}

func TestCertExpiryIsSecondsUntilNotAfterAndNegativeOnceExpired(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(certExpiryCollector{
		now: func() time.Time { return now },
		src: func() []CertExpiry {
			return []CertExpiry{
				{Site: "shop", Host: "shop.example.test", NotAfter: now.Add(90 * time.Second)},
				{Site: "shop", Host: "www.example.test", NotAfter: now.Add(-time.Minute)},
			}
		},
	}))

	assert.Equal(t, map[string]float64{
		"host=shop.example.test,site=shop": 90,
		"host=www.example.test,site=shop":  -60,
	}, samples(t, reg, "sherlock_cert_expiry_seconds"))
}

func TestRegisterReplacesThePreviousSource(t *testing.T) {
	saved := Registry
	defer func() { Registry = saved }()
	Registry = prometheus.NewRegistry()

	RegisterUpstreamHealth(func() []UpstreamStatus { return []UpstreamStatus{{Site: "old", Upstream: "a:1", Healthy: true}} })
	RegisterUpstreamHealth(func() []UpstreamStatus { return []UpstreamStatus{{Site: "new", Upstream: "b:1", Healthy: true}} })
	RegisterCertExpiry(func() []CertExpiry { return []CertExpiry{{Site: "old", Host: "a", NotAfter: time.Now()}} })
	RegisterCertExpiry(func() []CertExpiry { return []CertExpiry{{Site: "new", Host: "b", NotAfter: time.Now()}} })

	assert.Equal(t, map[string]float64{"site=new,upstream=b:1": 1}, samples(t, Registry, "sherlock_upstream_healthy"))
	assert.Len(t, samples(t, Registry, "sherlock_cert_expiry_seconds"), 1, "re-registering must not duplicate series")
}
