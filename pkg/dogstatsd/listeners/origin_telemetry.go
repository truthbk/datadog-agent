package listeners

import (
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var (
	tlmOriginBytes = telemetry.NewCounter("dogstatsd", "origin_bytes",
		[]string{"origin"}, "Bytes count per origin")
	tlmOriginPackets = telemetry.NewCounter("dogstatsd", "origin_packets",
		[]string{"origin"}, "Packets count per origin")
	tlmOriginTags = telemetry.NewCounter("dogstatsd", "origin_tags",
		[]string{"origin"}, "Tags count per origin")
	tlmOriginMetrics = telemetry.NewCounter("dogstatsd", "origin_metrics",
		[]string{"origin"}, "Metrics count per origin")
)

// OriginTelemetryEntry is created while processing a packet, meaning we have
// one OriginTelemetryEntry per packet.
type OriginTelemetryEntry struct {
	Origin       string
	BytesCount   uint
	TagsCount    uint
	MetricsCount uint
}

type OriginTelemetryTracker struct {
	ch           chan OriginTelemetryEntry
	stopChan     chan bool
	packetsCount map[string]uint
	bytesCount   map[string]uint
	tagsCount    map[string]uint
	metricsCount map[string]uint
}

func StartOriginTelemetry(stopChan chan bool) *OriginTelemetryTracker {
	trackingCh := make(chan OriginTelemetryEntry, 8192)
	tracker := &OriginTelemetryTracker{
		ch:           trackingCh,
		stopChan:     stopChan,
		packetsCount: make(map[string]uint),
		bytesCount:   make(map[string]uint),
		tagsCount:    make(map[string]uint),
		metricsCount: make(map[string]uint),
	}
	go func() {
		tracker.run(trackingCh)
	}()
	return tracker
}

func (t *OriginTelemetryTracker) StopOriginTelemetry() {
	close(t.ch)
}

func (t *OriginTelemetryTracker) processEntry(entry OriginTelemetryEntry) {
	tlmOriginBytes.Add(float64(entry.BytesCount), entry.Origin)
	tlmOriginTags.Add(float64(entry.TagsCount), entry.Origin)
	tlmOriginMetrics.Add(float64(entry.MetricsCount), entry.Origin)
	tlmOriginPackets.Inc(entry.Origin)
}

func countCommasAndLineReturns(b []byte) (uint, uint) {
	var tags uint = 0
	var metrics uint = 1
	for i := 0; i < len(b); i++ {
		if b[i] == ',' {
			tags += 1
		} else if b[i] == '\n' {
			metrics += 1
		}
	}
	return tags, metrics
}

func (t *OriginTelemetryTracker) run(trackingCh chan OriginTelemetryEntry) {
	log.Debug("Starting the origin telemetry tracker")
	for {
		select {
		case entry := <-trackingCh:
			t.processEntry(entry)
		case <-t.stopChan:
			log.Debug("Closing the origin telemetry tracker")
			return
		}
	}
}
