// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package ebpf

import (
	"errors"
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
	lib "github.com/cilium/ebpf"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/cmd/system-probe/statsd"
	"github.com/DataDog/datadog-agent/pkg/network/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/native"
)

var ErrNotEnoughData = errors.New("not enough data")

// PerfMapStats contains the collected metrics for one event and one cpu in a perf buffer statistics map
type PerfMapStats struct {
	Bytes *atomic.Uint64
	Count *atomic.Uint64
	Lost  *atomic.Uint64
}

// NewPerfMapStats returns a new PerfMapStats correctly initialized
func NewPerfMapStats() PerfMapStats {
	return PerfMapStats{
		Bytes: atomic.NewUint64(0),
		Count: atomic.NewUint64(0),
		Lost:  atomic.NewUint64(0),
	}
}

// UnmarshalBinary parses a map entry and populates the current PerfMapStats instance
func (s *PerfMapStats) UnmarshalBinary(data []byte) error {
	if len(data) < 24 {
		return ErrNotEnoughData
	}
	s.Bytes = atomic.NewUint64(native.Endian.Uint64(data[0:8]))
	s.Count = atomic.NewUint64(native.Endian.Uint64(data[8:16]))
	s.Lost = atomic.NewUint64(native.Endian.Uint64(data[16:24]))
	return nil
}

// PerfBufferMonitor holds statistics about the number of lost and received events
type PerfBufferMonitor struct {
	statsMap *lib.Map
	// numCPU holds the current count of CPU
	numCPU  int
	mapName string
	mapTag  string

	// stats holds the collected user space metrics
	stats []PerfMapStats
	// kernelStats holds the aggregated kernel space metrics
	kernelStats []PerfMapStats
	// readLostEvents is the count of lost events, collected by reading the perf buffer.  Note that the
	// slices of Uint64 are properly aligned for atomic access, and are not moved after creation (they
	// are indexed by cpuid)
	readLostEvents []*atomic.Uint64
	// sortingErrorStats holds the count of events that indicate that at least 1 event is miss ordered
	//sortingErrorStats *atomic.Int64

	// lastTimestamp is used to track the timestamp of the last event retrieved from the perf map
	//lastTimestamp uint64
}

// newPerfBufferMonitor instantiates a new event statistics counter
func newPerfBufferMonitor(mapName string, mgr *manager.Manager, mgrOpts *manager.Options) (*PerfBufferMonitor, error) {
	pbm := PerfBufferMonitor{
		mapName: mapName,
		mapTag:  fmt.Sprintf("map:%s", mapName),
	}

	cpuCount, err := kernel.PossibleCPUs()
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch the host CPU count: %w", err)
	}
	pbm.numCPU = cpuCount

	statsMapName := fmt.Sprintf("%s_stats", pbm.mapName)
	found := false
	for _, m := range mgr.Maps {
		if m.Name == statsMapName {
			found = true
			break
		}
	}
	if !found {
		mgr.Maps = append(mgr.Maps, &manager.Map{Name: statsMapName})
	}

	mgrOpts.MapSpecEditors[statsMapName] = manager.MapSpecEditor{
		MaxEntries: uint32(pbm.numCPU),
		EditorFlag: manager.EditMaxEntries,
	}

	// Prepare user space counters
	var stats, kernelStats []PerfMapStats
	var usrLostEvents []*atomic.Uint64

	for i := 0; i < pbm.numCPU; i++ {
		stats = append(stats, NewPerfMapStats())
		kernelStats = append(kernelStats, NewPerfMapStats())
		usrLostEvents = append(usrLostEvents, atomic.NewUint64(0))
	}

	pbm.stats = stats
	pbm.kernelStats = kernelStats
	pbm.readLostEvents = usrLostEvents
	//pbm.sortingErrorStats = atomic.NewInt64(0)
	log.Debugf("monitoring perf ring buffer on %d CPUs", pbm.numCPU)
	return &pbm, nil
}

func (pbm *PerfBufferMonitor) Start(m *manager.Manager) error {
	statsMapName := fmt.Sprintf("%s_stats", pbm.mapName)
	if sm, ok, err := m.GetMap(statsMapName); !ok {
		return fmt.Errorf("unable to get perf buffer stats map %s: %w", statsMapName, err)
	} else {
		pbm.statsMap = sm
	}
	return nil
}

// getLostCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getLostCount(cpu int) uint64 {
	return pbm.readLostEvents[cpu].Load()
}

// GetLostCount returns the number of lost events for a given map and cpu. If a cpu of -1 is provided, the function will
// return the sum of all the lost events of all the cpus.
func (pbm *PerfBufferMonitor) GetLostCount(cpu int) uint64 {
	var total uint64

	switch {
	case cpu == -1:
		for i := range pbm.readLostEvents {
			total += pbm.getLostCount(i)
		}
	case cpu >= 0 && pbm.numCPU > cpu:
		total += pbm.getLostCount(cpu)
	}

	return total
}

// getKernelLostCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getKernelLostCount(cpu int) uint64 {
	return pbm.kernelStats[cpu].Lost.Load()
}

// GetKernelLostCount returns the number of lost events for a given map and cpu. If a cpu of -1 is provided, the function will
// return the sum of all the lost events of all the cpus.
func (pbm *PerfBufferMonitor) GetKernelLostCount(cpu int) uint64 {
	var total uint64

	// query the kernel maps
	_ = pbm.collectAndSendKernelStats(false)

	for cpuID := range pbm.kernelStats {
		if cpu == -1 || cpu == cpuID {
			total += pbm.getKernelLostCount(cpuID)
		}
	}

	return total
}

// getAndResetReadLostCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getAndResetReadLostCount(cpu int) uint64 {
	return pbm.readLostEvents[cpu].Swap(0)
}

// GetAndResetLostCount returns the number of lost events and resets the counter for a given map and cpu. If a cpu of -1 is
// provided, the function will reset the counters of all the cpus for the provided map, and return the sum of all the
// lost events of all the cpus of the provided map.
func (pbm *PerfBufferMonitor) GetAndResetLostCount(cpu int) uint64 {
	var total uint64

	switch {
	case cpu == -1:
		for i := range pbm.readLostEvents {
			total += pbm.getAndResetReadLostCount(i)
		}
	case cpu >= 0 && pbm.numCPU > cpu:
		total += pbm.getAndResetReadLostCount(cpu)
	}
	return total
}

// getEventCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getEventCount(cpu int) uint64 {
	return pbm.stats[cpu].Count.Load()
}

// getEventBytes is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getEventBytes(cpu int) uint64 {
	return pbm.stats[cpu].Bytes.Load()
}

// getKernelEventCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getKernelEventCount(cpu int) uint64 {
	return pbm.kernelStats[cpu].Count.Load()
}

// getEventBytes is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getKernelEventBytes(cpu int) uint64 {
	return pbm.kernelStats[cpu].Bytes.Load()
}

// getKernelEventCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) swapKernelEventCount(cpu int, value uint64) uint64 {
	return pbm.kernelStats[cpu].Count.Swap(value)
}

// getKernelEventBytes is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) swapKernelEventBytes(cpu int, value uint64) uint64 {
	return pbm.kernelStats[cpu].Bytes.Swap(value)
}

// getKernelLostCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) swapKernelLostCount(cpu int, value uint64) uint64 {
	return pbm.kernelStats[cpu].Lost.Swap(value)
}

// GetEventStats returns the number of received events of the specified type
func (pbm *PerfBufferMonitor) GetEventStats(cpu int) (PerfMapStats, PerfMapStats) {
	stats, kernelStats := NewPerfMapStats(), NewPerfMapStats()

	switch {
	case cpu == -1:
		for i := range pbm.stats {
			stats.Count.Add(pbm.getEventCount(i))
			stats.Bytes.Add(pbm.getEventBytes(i))

			kernelStats.Count.Add(pbm.getKernelEventCount(i))
			kernelStats.Bytes.Add(pbm.getKernelEventBytes(i))
			kernelStats.Lost.Add(pbm.getKernelLostCount(i))
		}
	case cpu >= 0 && pbm.numCPU > cpu:
		stats.Count.Add(pbm.getEventCount(cpu))
		stats.Bytes.Add(pbm.getEventBytes(cpu))

		kernelStats.Count.Add(pbm.getKernelEventCount(cpu))
		kernelStats.Bytes.Add(pbm.getKernelEventBytes(cpu))
		kernelStats.Lost.Add(pbm.getKernelLostCount(cpu))
	}
	return stats, kernelStats
}

// getAndResetEventCount is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getAndResetEventCount(cpu int) uint64 {
	return pbm.stats[cpu].Count.Swap(0)
}

// getAndResetEventBytes is an internal function, it can segfault if its parameters are incorrect.
func (pbm *PerfBufferMonitor) getAndResetEventBytes(cpu int) uint64 {
	return pbm.stats[cpu].Bytes.Swap(0)
}

// getAndResetSortingErrorCount is an internal function, it can segfault if its parameters are incorrect.
//func (pbm *PerfBufferMonitor) getAndResetSortingErrorCount() int64 {
//	return pbm.sortingErrorStats.Swap(0)
//}

// CountLostEvent adds `count` to the counter of lost events
func (pbm *PerfBufferMonitor) CountLostEvent(count uint64, cpu int) {
	// sanity check
	if pbm.readLostEvents == nil || len(pbm.readLostEvents) <= cpu {
		return
	}
	pbm.readLostEvents[cpu].Add(count)
}

// CountEvent adds `count` to the counter of received events of the specified type
func (pbm *PerfBufferMonitor) CountEvent(count uint64, size uint64, cpu int) {
	// check event order
	//if timestamp < pbm.lastTimestamp && pbm.lastTimestamp != 0 {
	//	pbm.sortingErrorStats.Inc()
	//} else {
	//	pbm.lastTimestamp = timestamp
	//}

	// sanity check
	if pbm.stats == nil || len(pbm.stats) <= cpu {
		return
	}

	pbm.stats[cpu].Count.Add(count)
	pbm.stats[cpu].Bytes.Add(size)
}

func (pbm *PerfBufferMonitor) sendEventsAndBytesReadStats() error {
	var count int64
	var err error
	tags := []string{pbm.mapTag}

	for cpu := range pbm.stats {
		if count = int64(pbm.getAndResetEventCount(cpu)); count > 0 {
			if err = statsd.Client.Count(metrics.MetricPerfBufferEventsRead, count, tags, 1.0); err != nil {
				return err
			}
		}

		if count = int64(pbm.getAndResetEventBytes(cpu)); count > 0 {
			if err = statsd.Client.Count(metrics.MetricPerfBufferBytesRead, count, tags, 1.0); err != nil {
				return err
			}
		}

		//if count = pbm.getAndResetSortingErrorCount(); count > 0 {
		//	if err = statsd.Client.Count(metrics.MetricPerfBufferSortingError, count, tags, 1.0); err != nil {
		//		return err
		//	}
		//}
	}
	return nil
}

func (pbm *PerfBufferMonitor) sendLostEventsReadStats() error {
	tags := []string{pbm.mapTag}

	var total float64
	for cpu := range pbm.readLostEvents {
		if count := float64(pbm.getAndResetReadLostCount(cpu)); count > 0 {
			if err := statsd.Client.Count(metrics.MetricPerfBufferLostRead, int64(count), tags, 1.0); err != nil {
				return err
			}
			total += count
		}
	}
	return nil
}

func (pbm *PerfBufferMonitor) collectAndSendKernelStats(send bool) error {
	if pbm.statsMap == nil {
		return nil
	}

	tags := []string{pbm.mapTag}

	// loop through all the values of the active buffer
	iterator := pbm.statsMap.Iterate()

	var cpu uint32
	var stats PerfMapStats
	for iterator.Next(&cpu, &stats) {
		if err := pbm.collectAndSendKernelCPUStats(int(cpu), stats, send, tags); err != nil {
			return err
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("failed to dump the statistics buffer of %s: %w", pbm.mapTag, err)
	}

	return nil
}

func (pbm *PerfBufferMonitor) collectAndSendKernelCPUStats(cpu int, stats PerfMapStats, send bool, tags []string) error {
	var tmpCount uint64
	// Update stats to avoid sending twice the same data points
	if tmpCount = pbm.swapKernelEventBytes(cpu, stats.Bytes.Load()); tmpCount <= stats.Bytes.Load() {
		stats.Bytes.Sub(tmpCount)
	}
	if tmpCount = pbm.swapKernelEventCount(cpu, stats.Count.Load()); tmpCount <= stats.Count.Load() {
		stats.Count.Sub(tmpCount)
	}
	if tmpCount = pbm.swapKernelLostCount(cpu, stats.Lost.Load()); tmpCount <= stats.Lost.Load() {
		stats.Lost.Sub(tmpCount)
	}

	if send {
		if err := pbm.sendKernelStats(stats, tags); err != nil {
			return err
		}
	}
	return nil
}

func (pbm *PerfBufferMonitor) sendKernelStats(stats PerfMapStats, tags []string) error {
	if stats.Count.Load() > 0 {
		if err := statsd.Client.Count(metrics.MetricPerfBufferEventsWrite, int64(stats.Count.Load()), tags, 1.0); err != nil {
			return err
		}
	}

	if stats.Bytes.Load() > 0 {
		if err := statsd.Client.Count(metrics.MetricPerfBufferBytesWrite, int64(stats.Bytes.Load()), tags, 1.0); err != nil {
			return err
		}
	}

	if stats.Lost.Load() > 0 {
		if err := statsd.Client.Count(metrics.MetricPerfBufferLostWrite, int64(stats.Lost.Load()), tags, 1.0); err != nil {
			return err
		}
	}

	return nil
}

// SendStats send event stats using the provided statsd client
func (pbm *PerfBufferMonitor) SendStats() error {
	if err := pbm.collectAndSendKernelStats(true); err != nil {
		return err
	}

	if err := pbm.sendEventsAndBytesReadStats(); err != nil {
		return err
	}

	return pbm.sendLostEventsReadStats()
}
