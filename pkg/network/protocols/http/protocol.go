package http

import (
	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/events"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	httpInFlightMap = "http_in_flight"
)

type HttpProtocol struct {
	networkConfig *config.Config

	consumer   *events.Consumer // For consuming transactions from the eBPF program
	telemetry  *telemetry
	statkeeper *httpStatKeeper
	mapCleaner *ddebpf.MapCleaner
}

func NewHTTPProtocol(config *config.Config) (protocols.Protocol, error) {
	telemetry, err := newTelemetry()
	if err != nil {
		return nil, err
	}

	return &HttpProtocol{
		networkConfig: config,
		telemetry:     telemetry,
		statkeeper:    newHTTPStatkeeper(config, telemetry),
	}, nil
}

func (protocol *HttpProtocol) ConfigureEbpfManager(program *EbpfProgram, options *manager.Options) error {
	maps := program.Manager.Maps
	maps = append(maps, &manager.Map{Name: httpInFlightMap})

	options.TailCallRouter = append(options.TailCallRouter,
		manager.TailCallRoute{
			ProgArrayName: protocolDispatcherProgramsMap,
			Key:           uint32(ProtocolHTTP),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "socket__http_filter",
			},
		},
	)

	options.MapSpecEditors[httpInFlightMap] = manager.MapSpecEditor{
		Type:       ebpf.Hash,
		MaxEntries: uint32(protocol.networkConfig.MaxTrackedConnections),
		EditorFlag: manager.EditMaxEntries,
	}

	events.Configure("http", program.Manager.Manager, options)

	return nil
}

func (protocol *HttpProtocol) PreStart(program *EbpfProgram) error {
	var err error
	protocol.consumer, err = events.NewConsumer(
		"http",
		program.Manager.Manager,
		protocol.processHTTP,
	)
	if err != nil {
		return err
	}
	protocol.consumer.Start()
	return nil
}

func (protocol *HttpProtocol) PostStart(program *EbpfProgram) error {
	protocol.setupMapCleaner(program)
	return nil
}

func (protocol *HttpProtocol) PreClose(program *EbpfProgram) error {
	protocol.mapCleaner.Stop()
	return nil
}

func (protocol *HttpProtocol) PostClose(program *EbpfProgram) error {
	protocol.consumer.Stop()
	return nil
}

func (protocol *HttpProtocol) GetStats() map[Key]*RequestStats {
	if protocol == nil {
		return nil
	}

	protocol.consumer.Sync()
	protocol.telemetry.log()
	return protocol.statkeeper.GetAndResetAllStats()
}

func (protocol *HttpProtocol) processHTTP(data []byte) {
	tx := (*ebpfHttpTx)(unsafe.Pointer(&data[0]))
	protocol.telemetry.count(tx)
	protocol.statkeeper.Process(tx)
}

func (protocol *HttpProtocol) setupMapCleaner(e *EbpfProgram) {
	httpMap, _, _ := e.GetMap(httpInFlightMap)
	httpMapCleaner, err := ddebpf.NewMapCleaner(httpMap, new(netebpf.ConnTuple), new(ebpfHttpTx))
	if err != nil {
		_ = log.Errorf("error creating map cleaner: %s", err)
		return
	}

	ttl := e.cfg.HTTPIdleConnectionTTL.Nanoseconds()
	httpMapCleaner.Clean(e.cfg.HTTPMapCleanerInterval, func(now int64, key, val interface{}) bool {
		httpTxn, ok := val.(*ebpfHttpTx)
		if !ok {
			return false
		}

		if updated := int64(httpTxn.ResponseLastSeen()); updated > 0 {
			return (now - updated) > ttl
		}

		started := int64(httpTxn.RequestStarted())
		return started > 0 && (now-started) > ttl
	})

	e.mapCleaner = httpMapCleaner
}
