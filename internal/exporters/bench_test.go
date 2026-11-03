package exporters

import (
	"testing"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/events"
)

// The pair below is the M10 AC2 evidence at the bus: publishing must cost the
// same whether a stuck exporter is attached or not (compare the two results
// with make bench-gate). Request latency is bus.Publish plus nothing else.

func benchPublish(b *testing.B, attach func(bus *events.Bus)) {
	bus := events.NewBus(events.DefaultBusCapacity)
	attach(bus)
	ev := &events.Event{ID: "x", Schema: events.SchemaV1, TS: time.Now()}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bus.Publish(ev)
		}
	})
}

func BenchmarkPublishNoExporter(b *testing.B) {
	benchPublish(b, func(*events.Bus) {})
}

func BenchmarkPublishStuckExporter(b *testing.B) {
	benchPublish(b, func(bus *events.Bus) {
		f := &fake{block: make(chan struct{})}
		r, err := NewRunner("x", "X", "fake", StreamEvents, f, bus, b.TempDir(), RunnerOptions{}, quiet)
		if err != nil {
			b.Fatal(err)
		}
		r.Start(b.Context())
		b.Cleanup(func() { close(f.block); r.Stop() })
	})
}
