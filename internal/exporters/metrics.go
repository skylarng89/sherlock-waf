package exporters

import "github.com/prometheus/client_golang/prometheus"

var (
	descSent = prometheus.NewDesc("sherlock_exporter_sent_total",
		"Records accepted by the exporter's destination.", []string{"exporter", "type"}, nil)
	descFailures = prometheus.NewDesc("sherlock_exporter_send_failures_total",
		"Failed delivery attempts (each is retried with backoff).", []string{"exporter", "type"}, nil)
	descDropped = prometheus.NewDesc("sherlock_exporter_dropped_total",
		"Records that will never be delivered, by reason: spool_full, lagged (bus ring overrun), rejected (destination refused the batch or the record was unreadable).",
		[]string{"exporter", "type", "reason"}, nil)
	descPending = prometheus.NewDesc("sherlock_exporter_pending",
		"Records spooled and not yet delivered.", []string{"exporter", "type"}, nil)
	descSpoolBytes = prometheus.NewDesc("sherlock_exporter_spool_bytes",
		"Bytes held in the exporter's disk spool.", []string{"exporter", "type"}, nil)
	descSpoolMax = prometheus.NewDesc("sherlock_exporter_spool_max_bytes",
		"Configured cap of the exporter's disk spool (spool_max_mb); the oldest segment is dropped beyond it.", []string{"exporter", "type"}, nil)
	descLastSuccess = prometheus.NewDesc("sherlock_exporter_last_success_timestamp_seconds",
		"Unix time of the last accepted batch; 0 if none yet.", []string{"exporter", "type"}, nil)
)

// RegisterMetrics exposes m's exporters on reg, replacing any earlier
// registration. A series disappears when its exporter is removed.
func RegisterMetrics(reg *prometheus.Registry, m *Manager) {
	reg.Unregister(collector{})
	reg.MustRegister(collector{m})
}

type collector struct{ m *Manager }

func (collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descSent, descFailures, descDropped, descPending, descSpoolBytes, descSpoolMax, descLastSuccess} {
		ch <- d
	}
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.m.Status() {
		l := []string{s.ID, s.Type}
		ch <- prometheus.MustNewConstMetric(descSent, prometheus.CounterValue, float64(s.Sent), l...)
		ch <- prometheus.MustNewConstMetric(descFailures, prometheus.CounterValue, float64(s.SendFailures), l...)
		ch <- prometheus.MustNewConstMetric(descDropped, prometheus.CounterValue, float64(s.SpoolDropped), s.ID, s.Type, "spool_full")
		ch <- prometheus.MustNewConstMetric(descDropped, prometheus.CounterValue, float64(s.Lagged), s.ID, s.Type, "lagged")
		ch <- prometheus.MustNewConstMetric(descDropped, prometheus.CounterValue, float64(s.Discarded), s.ID, s.Type, "rejected")
		ch <- prometheus.MustNewConstMetric(descPending, prometheus.GaugeValue, float64(s.Pending), l...)
		ch <- prometheus.MustNewConstMetric(descSpoolBytes, prometheus.GaugeValue, float64(s.SpoolBytes), l...)
		ch <- prometheus.MustNewConstMetric(descSpoolMax, prometheus.GaugeValue, float64(s.SpoolMaxBytes), l...)
		var ts float64
		if !s.LastSuccess.IsZero() {
			ts = float64(s.LastSuccess.UnixNano()) / 1e9
		}
		ch <- prometheus.MustNewConstMetric(descLastSuccess, prometheus.GaugeValue, ts, l...)
	}
}
