// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package ebpf

import (
	"fmt"
	"sync"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf/perf"

	"github.com/DataDog/datadog-agent/cmd/system-probe/statsd"
	"github.com/DataDog/datadog-agent/pkg/network/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var recordPool = sync.Pool{
	New: func() interface{} {
		return &perf.Record{}
	},
}

// PerfMap represents a perf buffer with its associated stats monitoring.
type PerfMap struct {
	name    string
	mgr     *manager.Manager
	perfMap *manager.PerfMap
	handler func(int, []byte)

	mon               *PerfBufferMonitor
	reportingInterval time.Duration

	Done chan struct{}
	once sync.Once
}

// NewPerfMap creates an abstraction around a perf buffer and the stats monitoring for it.
// It will add the map and its associated stats map to the eBPF manager automatically.
func NewPerfMap(name string, mgr *manager.Manager, opts *manager.Options) (*PerfMap, error) {
	p := &PerfMap{
		name:              name,
		mgr:               mgr,
		Done:              make(chan struct{}),
		reportingInterval: 10 * time.Second,
	}

	var ok bool
	if p.perfMap, ok = mgr.GetPerfMap(name); !ok {
		p.perfMap = &manager.PerfMap{
			Map: manager.Map{Name: name},
		}
		mgr.PerfMaps = append(mgr.PerfMaps, p.perfMap)
	}

	p.perfMap.PerfMapOptions = manager.PerfMapOptions{
		RecordHandler: p.handleRecord,
		LostHandler:   p.handleLostEvent,
		RecordGetter: func() *perf.Record {
			return recordPool.Get().(*perf.Record)
		},
	}

	var err error
	if p.mon, err = newPerfBufferMonitor(name, mgr, opts); err != nil {
		return nil, fmt.Errorf("error creating perf buffer monitor for %s: %w", name, err)
	}

	return p, nil
}

func (p *PerfMap) handleRecord(record *perf.Record, _ *manager.PerfMap, _ *manager.Manager) {
	defer recordPool.Put(record)

	p.mon.CountEvent(1, uint64(len(record.RawSample)), record.CPU)
	p.handler(record.CPU, record.RawSample)
}

func (p *PerfMap) handleLostEvent(CPU int, lostCount uint64, _ *manager.PerfMap, _ *manager.Manager) {
	p.mon.CountLostEvent(lostCount, CPU)
}

// Start monitoring the perf buffer and setup the data handler.
// This should be called before calling Start on the eBPF manager.
func (p *PerfMap) Start(handler func(int, []byte)) error {
	if err := p.mon.Start(p.mgr); err != nil {
		return fmt.Errorf("error starting perf buffer monitor for %s: %w", p.name, err)
	}
	go func() {
		t := time.NewTicker(p.reportingInterval)
		defer t.Stop()

		select {
		case <-t.C:
			if err := p.mon.SendStats(); err != nil {
				log.Warnf("error sending perf buffer stats for %s: %s", p.name, err)
			}
		case <-p.Done:
			return
		}
	}()
	p.handler = handler
	return nil
}

// Stop stops monitoring the perf buffer. It does not affect the underlying eBPF resources.
// That should be handled by the eBPF manager.
func (p *PerfMap) Stop() {
	p.once.Do(func() {
		close(p.Done)
	})
}

// DataEvent wraps a perf buffer record
type DataEvent struct {
	CPU  int
	Data []byte

	r *perf.Record
}

// Done indicates that data processing is done, and the memory can be reclaimed
func (d *DataEvent) Done() {
	recordPool.Put(d.r)
}

// ChannelPerfMap wraps PerfMap to provide the data over a buffered channel.
type ChannelPerfMap struct {
	*PerfMap
	DataChannel chan *DataEvent
	closed      bool
}

// NewChannelPerfMap creates a perf map which exposes its data over a buffered channel of the provided size.
// See NewPerfMap for more details.
//nolint:unused,deadcode
func NewChannelPerfMap(name string, mgr *manager.Manager, opts *manager.Options, chanSize int) (*ChannelPerfMap, error) {
	p, err := NewPerfMap(name, mgr, opts)
	if err != nil {
		return nil, err
	}

	cp := &ChannelPerfMap{
		PerfMap:     p,
		DataChannel: make(chan *DataEvent, chanSize),
	}
	cp.perfMap.PerfMapOptions.RecordHandler = cp.handleRecord
	return cp, nil
}

func (p *ChannelPerfMap) handleRecord(record *perf.Record, _ *manager.PerfMap, _ *manager.Manager) {
	if p.closed {
		recordPool.Put(record)
		return
	}
	p.mon.CountEvent(1, uint64(len(record.RawSample)), record.CPU)
	p.DataChannel <- &DataEvent{CPU: record.CPU, Data: record.RawSample, r: record}
}

// Start monitoring the perf buffer and setup the data handler.
// This should be called before calling Start on the eBPF manager.
func (p *ChannelPerfMap) Start() error {
	if err := p.PerfMap.Start(nil); err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(p.reportingInterval)
		defer t.Stop()

		select {
		case <-t.C:
			if err := statsd.Client.Count(metrics.MetricPerfBufferEventsChannel, int64(len(p.DataChannel)), []string{"map:" + p.name}, 1.0); err != nil {
				log.Debugf("error sending perf channel length: %s", err)
			}
		case <-p.Done:
			return
		}
	}()

	return nil
}

// Stop stops monitoring the perf buffer. It does not affect the underlying eBPF resources.
// That should be handled by the eBPF manager.
func (p *ChannelPerfMap) Stop() {
	p.once.Do(func() {
		p.closed = true
		close(p.Done)
		close(p.DataChannel)
	})
}
