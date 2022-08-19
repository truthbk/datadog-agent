// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"

	manager "github.com/DataDog/ebpf-manager"
)

type reOrdererNodePool struct {
	head *reOrdererNode
}

func (p *reOrdererNodePool) alloc() *reOrdererNode {
	node := p.head
	if node != nil && node.timestamp == 0 {
		p.head = node.nextFree
		node.record = nil
		return node
	}

	return &reOrdererNode{}
}

func (p *reOrdererNodePool) free(node *reOrdererNode) {
	node.timestamp = 0
	node.record = nil

	if p.head == nil {
		p.head = node
	} else {
		node.nextFree = p.head
		p.head = node
	}
}

type reOrdererNode struct {
	timestamp  uint64
	record     *perf.Record
	nextFree   *reOrdererNode
	generation uint64
}

type reOrdererList struct {
	list []*reOrdererNode
	pool *reOrdererNodePool
}

func (h *reOrdererList) len() uint64 {
	return uint64(len(h.list))
}

func (h *reOrdererList) enqueue(record *perf.Record, tm uint64, generation uint64, metric *ReOrdererMetric) {
	node := h.pool.alloc()
	node.timestamp = tm
	node.record = record
	node.generation = generation

	metric.TotalOp++

	if len(h.list) == 0 {
		h.list = append(h.list, node)
		return
	}

	last := h.list[len(h.list)-1]
	if last.timestamp <= node.timestamp && last.generation <= node.generation {
		h.list = append(h.list, node)
		return
	}

	i := sort.Search(len(h.list), func(i int) bool {
		return h.list[i].timestamp >= node.timestamp
	})

	h.list = append(h.list, nil)
	copy(h.list[i+1:], h.list[i:])
	h.list[i] = node

	before := i - 1
	after := i + 1
	if (before < 0 || h.list[before].generation <= node.generation) &&
		(after >= len(h.list) || node.generation <= h.list[after].generation) {
		return
	}

	for before >= 0 && h.list[before].generation > h.list[before+1].generation {
		h.list[before].generation, h.list[before+1].generation = h.list[before+1].generation, h.list[before].generation
		before--
	}

	for after < len(h.list) && h.list[after-1].generation > h.list[after].generation {
		h.list[after].generation, h.list[after-1].generation = h.list[after-1].generation, h.list[after].generation
		after++
	}
}

func (h *reOrdererList) dequeue(handler func(record *perf.Record), generation uint64, metric *ReOrdererMetric, opts *ReOrdererOpts) {
	var i int
	for _, node := range h.list {
		if node.generation > generation {
			break
		}

		metric.TotalOp++
		handler(node.record)

		h.pool.free(node)

		i++
	}

	if i == len(h.list) {
		h.list = h.list[:0]
		return
	}

	h.list = h.list[i:]
}

// ReOrdererOpts options to pass when creating a new instance of ReOrderer
type ReOrdererOpts struct {
	QueueSize       uint64        // size of the chan where the perf data are pushed
	Rate            time.Duration // delay between two time based iterations
	Retention       uint64        // bucket to keep before dequeueing
	MetricRate      time.Duration // delay between two metric samples
	HeapShrinkDelta int           // delta between cap and len between releasing heap array
}

func (r *ReOrdererMetric) zero() {
	// keep size of avoid overflow between queue/dequeue
	r.TotalDepth = 0
	r.TotalOp = 0
}

// ReOrdererMetric holds reordering metrics
type ReOrdererMetric struct {
	TotalOp    uint64
	TotalDepth uint64
	QueueSize  uint64
}

// ReOrderer defines an event re-orderer
type ReOrderer struct {
	ctx         context.Context
	queue       chan *perf.Record
	handler     func(*perf.Record)
	list        *reOrdererList
	extractInfo func(*perf.Record) (uint64, uint64, error) // timestamp
	opts        ReOrdererOpts
	metric      ReOrdererMetric
	Metrics     chan ReOrdererMetric
	generation  uint64
}

// Start event handler loop
func (r *ReOrderer) Start(wg *sync.WaitGroup) {
	defer wg.Done()

	flushTicker := time.NewTicker(r.opts.Rate)
	defer flushTicker.Stop()

	metricTicker := time.NewTicker(r.opts.MetricRate)
	defer metricTicker.Stop()

	var lastTm, tm uint64
	var err error

	for {
		select {
		case record := <-r.queue:
			if len(record.RawSample) > 0 {
				if _, tm, err = r.extractInfo(record); err != nil {
					continue
				}
			} else {
				tm = lastTm
			}

			if tm == 0 {
				continue
			}
			lastTm = tm

			if r.list.len() > r.opts.QueueSize*10 {
				r.handler(record)
			} else {
				r.list.enqueue(record, tm, r.generation, &r.metric)
			}
			r.list.dequeue(r.handler, r.generation-r.opts.Retention, &r.metric, &r.opts)
		case <-flushTicker.C:
			r.generation++

			// force dequeue of a generation in case of low event rate
			r.list.dequeue(r.handler, r.generation-r.opts.Retention, &r.metric, &r.opts)
		case <-metricTicker.C:
			r.metric.QueueSize = uint64(r.list.len())

			select {
			case r.Metrics <- r.metric:
			default:
			}

			r.metric.zero()
		case <-r.ctx.Done():
			return
		}
	}
}

// HandleEvent handle event form perf ring
func (r *ReOrderer) HandleEvent(record *perf.Record, perfMap *manager.PerfMap, manager *manager.Manager) {
	select {
	case r.queue <- record:
		return
	case <-r.ctx.Done():
		return
	}
}

// NewReOrderer returns a new ReOrderer
func NewReOrderer(ctx context.Context, handler func(record *perf.Record), extractInfo func(record *perf.Record) (uint64, uint64, error), opts ReOrdererOpts) *ReOrderer {
	return &ReOrderer{
		ctx:     ctx,
		queue:   make(chan *perf.Record, opts.QueueSize),
		handler: handler,
		list: &reOrdererList{
			pool: &reOrdererNodePool{},
		},
		extractInfo: extractInfo,
		opts:        opts,
		Metrics:     make(chan ReOrdererMetric, 10),
		generation:  opts.Retention * 2, // start with retention to avoid direct dequeue at start
	}
}
