// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"expvar"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/listeners"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/packets"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd/replay"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/tagset"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/prometheus/statsd_exporter/pkg/mapper"
	"go.uber.org/fx"
)

var (
	dogstatsdExpvars                  = expvar.NewMap("dogstatsd")
	dogstatsdServiceCheckParseErrors  = expvar.Int{}
	dogstatsdServiceCheckPackets      = expvar.Int{}
	dogstatsdEventParseErrors         = expvar.Int{}
	dogstatsdEventPackets             = expvar.Int{}
	dogstatsdMetricParseErrors        = expvar.Int{}
	dogstatsdMetricPackets            = expvar.Int{}
	dogstatsdPacketsLastSec           = expvar.Int{}
	dogstatsdUnterminatedMetricErrors = expvar.Int{}

	tlmProcessed = telemetry.NewCounter("dogstatsd", "processed",
		[]string{"message_type", "state", "origin"}, "Count of service checks/events/metrics processed by dogstatsd")
	tlmProcessedOk    = tlmProcessed.WithValues("metrics", "ok", "")
	tlmProcessedError = tlmProcessed.WithValues("metrics", "error", "")

	// while we try to add the origin tag in the tlmProcessed metric, we want to
	// avoid having it growing indefinitely, hence this safeguard to limit the
	// size of this cache for long-running agent or environment with a lot of
	// different container IDs.
	maxOriginCounters = 200

	tlmChannel            = telemetry.NewHistogramNoOp()
	defaultChannelBuckets = []float64{100, 250, 500, 1000, 10000}
	once                  sync.Once
)

type dependencies struct {
	fx.In

	Log    log.Component
	Params Params
}

// When the internal telemetry is enabled, used to tag the origin
// on the processed metric.
type cachedOriginCounter struct {
	origin string
	ok     map[string]string
	err    map[string]string
	okCnt  telemetry.SimpleCounter
	errCnt telemetry.SimpleCounter
}

type server struct {
	server *dogstatsd.Server
}

// Server represent a Dogstatsd server
type Server struct {
	// listeners are the instantiated socket listener (UDS or UDP or both)
	listeners []listeners.StatsdListener

	// demultiplexer will receive the metrics processed by the DogStatsD server,
	// will take care of processing them concurrently if possible, and will
	// also take care of forwarding the metrics to the intake.
	demultiplexer aggregator.Demultiplexer

	// running in their own routine, workers are responsible of parsing the packets
	// and pushing them to the aggregator
	workers []*worker

	packetsIn               chan packets.Packets
	captureChan             chan packets.Packets
	serverlessFlushChan     chan bool
	sharedPacketPool        *packets.Pool
	sharedPacketPoolManager *packets.PoolManager
	sharedFloat64List       *float64ListPool
	Statistics              *util.Stats
	Started                 bool
	stopChan                chan bool
	health                  *health.Handle
	histToDist              bool
	histToDistPrefix        string
	extraTags               []string
	Debug                   *DsdServerDebug
	debugTagsAccumulator    *tagset.HashingTagsAccumulator
	TCapture                *replay.TrafficCapture
	mapper                  *mapper.MetricMapper
	eolTerminationUDP       bool
	eolTerminationUDS       bool
	eolTerminationNamedPipe bool
	// disableVerboseLogs is a feature flag to disable the logs capable
	// of flooding the logger output (e.g. parsing messages error).
	// NOTE(remy): this should probably be dropped and use a throttler logger, see
	// package (pkg/trace/log/throttled.go) for a possible throttler implementation.
	disableVerboseLogs bool

	// cachedTlmLock must be held when accessing cachedOriginCounters and cachedOrder
	cachedTlmLock sync.Mutex
	// cachedOriginCounters caches telemetry counter per origin
	// (when dogstatsd origin telemetry is enabled)
	cachedOriginCounters map[string]cachedOriginCounter
	cachedOrder          []cachedOriginCounter // for cache eviction

	// ServerlessMode is set to true if we're running in a serverless environment.
	ServerlessMode     bool
	UdsListenerRunning bool

	// originTelemetry is true if we want to report telemetry per origin.
	originTelemetry bool

	enrichConfig enrichConfig
}

func newServer(deps dependencies) Component {
	return &server{server: dogstatsd.NewServer(deps.Params.Serverless)}
}

func (s *server) Start(demultiplexer aggregator.Demultiplexer) error {
	return s.server.Start(demultiplexer)

}
func (s *server) Stop() {
	s.server.Stop()
}

func (s *server) IsRunning() bool {
	return s.server.Started
}

func (s *server) Capture(p string, d time.Duration, compressed bool) (string, error) {

	err := s.server.Capture(p, d, compressed)
	if err != nil {
		return "", err
	}

	// wait for the capture to start
	for !s.server.TCapture.IsOngoing() {
		time.Sleep(500 * time.Millisecond)
	}

	path, err := s.server.TCapture.Path()

	return path, err
}

func (s *server) GetJSONDebugStats() ([]byte, error) {
	return s.server.GetJSONDebugStats()
}

func (s *server) IsDebugEnabled() bool {
	return s.server.Debug.Enabled.Load()
}

func (s *server) EnableMetricsStats() {
	s.server.EnableMetricsStats()
}

func (s *server) DisableMetricsStats() {
	s.server.DisableMetricsStats()
}

func (s *server) UdsListenerRunning() bool {
	return s.server.UdsListenerRunning
}
