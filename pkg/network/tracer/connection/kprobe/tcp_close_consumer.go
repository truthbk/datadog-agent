// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package kprobe

import (
	"sync"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
)

const (
	perfReceivedStat = "perf_recv"
	perfLostStat     = "perf_lost"
)

type tcpCloseConsumer struct {
	m            *manager.Manager
	perfMap      *netebpf.ChannelPerfMap
	batchManager *perfBatchManager
	requests     chan chan struct{}
	buffer       *network.ConnectionBuffer
	once         sync.Once
}

func newTCPCloseConsumer(cfg *config.Config, m *manager.Manager, opts *manager.Options) (*tcpCloseConsumer, error) {
	closedChannelSize := defaultClosedChannelSize
	if cfg.ClosedChannelSize > 0 {
		closedChannelSize = cfg.ClosedChannelSize
	}
	perfMap, err := netebpf.NewChannelPerfMap(string(probes.ConnCloseEventMap), m, opts, closedChannelSize)
	if err != nil {
		return nil, err
	}
	connCloseMap, _, err := m.GetMap(string(probes.ConnCloseBatchMap))
	if err != nil {
		return nil, err
	}
	batchManager, err := newPerfBatchManager(connCloseMap)
	if err != nil {
		return nil, err
	}

	return &tcpCloseConsumer{
		requests:     make(chan chan struct{}),
		perfMap:      perfMap,
		batchManager: batchManager,
		buffer:       network.NewConnectionBuffer(netebpf.BatchSize, netebpf.BatchSize),
	}, nil
}

func (c *tcpCloseConsumer) FlushPending() {
	if c == nil {
		return
	}

	wait := make(chan struct{})
	c.requests <- wait
	<-wait
}

func (c *tcpCloseConsumer) GetStats() map[string]int64 {
	return map[string]int64{}
}

func (c *tcpCloseConsumer) Stop() {
	if c == nil {
		return
	}
	c.perfMap.Stop()
	c.once.Do(func() {
		close(c.requests)
	})
}

func (c *tcpCloseConsumer) Start(callback func([]network.ConnectionStats)) error {
	if c == nil {
		return nil
	}
	err := c.perfMap.Start()
	if err != nil {
		return err
	}

	//var (
	//	then        = time.Now()
	//	closedCount int
	//	lostCount   int
	//)
	go func() {
		for {
			select {
			case batchData, ok := <-c.perfMap.DataChannel:
				if !ok {
					return
				}
				batch := netebpf.ToBatch(batchData.Data)
				c.batchManager.ExtractBatchInto(c.buffer, batch, batchData.CPU)
				//closedCount += c.buffer.Len()
				callback(c.buffer.Connections())
				c.buffer.Reset()
				batchData.Done()
			//case _, ok := <-c.perfHandler.LostChannel:
			//	if !ok {
			//		return
			//	}
			//	lostCount += netebpf.BatchSize
			case request, ok := <-c.requests:
				if !ok {
					return
				}

				oneTimeBuffer := network.NewConnectionBuffer(32, 32)
				c.batchManager.GetPendingConns(oneTimeBuffer)
				callback(oneTimeBuffer.Connections())
				close(request)

				//closedCount += oneTimeBuffer.Len()
				//now := time.Now()
				//elapsed := now.Sub(then)
				//then = now
				//log.Debugf(
				//	"tcp close summary: closed_count=%d elapsed=%s closed_rate=%.2f/s lost_count=%d",
				//	closedCount,
				//	elapsed,
				//	float64(closedCount)/elapsed.Seconds(),
				//	lostCount,
				//)
				//closedCount = 0
				//lostCount = 0
			}
		}
	}()

	return nil
}
