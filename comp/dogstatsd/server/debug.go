// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator/ckey"
	"github.com/benbjohnson/clock"
	"go.uber.org/atomic"
)

// metricStat holds how many times a metric has been
// processed and when was the last time.
type metricStat struct {
	Name     string    `json:"name"`
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	Tags     string    `json:"tags"`
}

type DsdServerDebug struct {
	sync.Mutex
	Enabled *atomic.Bool
	Stats   map[ckey.ContextKey]metricStat `json:"stats"`
	// counting number of metrics processed last X seconds
	metricsCounts metricsCountBuckets
	// keyGen is used to generate hashes of the metrics received by dogstatsd
	keyGen *ckey.KeyGenerator

	// clock is used to keep a consistent time state within the debug server whether
	// we use a real clock in production code or a mock clock for unit testing
	clock clock.Clock
}

// newDSDServerDebug creates a new instance of a DsdServerDebug
func newDSDServerDebug() *DsdServerDebug {
	return newDSDServerDebugWithClock(clock.New())
}

// newDSDServerDebugWithClock creates a new instance of a DsdServerDebug with a specific clock
// It is used to create a DsdServerDebug with a real clock for production code and with a mock clock for testing code
func newDSDServerDebugWithClock(clock clock.Clock) *DsdServerDebug {
	return &DsdServerDebug{
		Enabled: atomic.NewBool(false),
		Stats:   make(map[ckey.ContextKey]metricStat),
		metricsCounts: metricsCountBuckets{
			counts:     [5]uint64{0, 0, 0, 0, 0},
			metricChan: make(chan struct{}),
			closeChan:  make(chan struct{}),
		},
		keyGen: ckey.NewKeyGenerator(),
		clock:  clock,
	}
}

// metricsCountBuckets is counting the amount of metrics received for the last 5 seconds.
// It is used to detect spikes.
type metricsCountBuckets struct {
	counts     [5]uint64
	bucketIdx  int
	currentSec time.Time
	metricChan chan struct{}
	closeChan  chan struct{}
}
