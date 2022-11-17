// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"errors"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util/watermark"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// RunnerConfig implements config for runners that work with CheckWithRealTime
type RunnerConfig struct {
	CheckInterval time.Duration
	RtInterval    time.Duration

	ExitChan       chan struct{}
	RtIntervalChan chan time.Duration
	RtEnabled      func() bool
	RunCheck       func(options RunOptions)
}

type runnerWithRealTime struct {
	RunnerConfig
	ratio      int
	counter    int
	newTicker  func(d time.Duration) *time.Ticker
	stopTicker func(t *time.Ticker)
}

type runnerWithWatermark struct {
	RunnerConfig
	watermarkChan        <-chan *watermark.Signal
	shouldRunOnWatermark ShouldRunOnWatermark

	checkRunTicker func(d time.Duration) *time.Ticker
	stopTicker     func(t *time.Ticker)
}

// NewRunnerWithRealTime creates a runner func for CheckWithRealTime
func NewRunnerWithRealTime(config RunnerConfig) (func(), error) {
	_, err := getRtRatio(config.CheckInterval, config.RtInterval)
	if err != nil {
		return nil, err
	}
	r := &runnerWithRealTime{
		RunnerConfig: config,
		newTicker:    time.NewTicker,
		stopTicker: func(t *time.Ticker) {
			t.Stop()
		},
	}
	return r.run, nil
}

// run performs runs for CheckWithRealTime checks
func (r *runnerWithRealTime) run() {
	var err error
	r.ratio, err = getRtRatio(r.CheckInterval, r.RtInterval)
	if err != nil {
		return
	}

	// Run the check the first time to prime the caches.
	r.RunCheck(RunOptions{
		RunStandard: true,
	})

	ticker := r.newTicker(r.RtInterval)
	for {
		select {
		case <-ticker.C:
			if r.counter == r.ratio {
				r.counter = 0
			}

			rtEnabled := r.RtEnabled()
			if rtEnabled || r.counter == 0 {
				r.RunCheck(RunOptions{
					RunStandard: r.counter == 0,
					RunRealTime: rtEnabled,
				})
			}

			r.counter++
		case d := <-r.RtIntervalChan:
			// Live-update the ticker.
			newRatio, err := getRtRatio(r.CheckInterval, d)
			if err != nil {
				log.Errorf("failed to apply new RT interval: %v", err)
				continue
			}
			r.RtInterval = d
			r.stopTicker(ticker)
			ticker = r.newTicker(d)

			r.ratio = newRatio
			r.counter = 0
		case _, ok := <-r.ExitChan:
			if !ok {
				return
			}
		}
	}
}

func getRtRatio(checkInterval, rtInterval time.Duration) (int, error) {
	if checkInterval < rtInterval {
		return -1, errors.New("check interval should be larger or equal to RT interval")
	}
	if checkInterval%rtInterval != 0 {
		return -1, errors.New("check interval should be divisible by RT interval")
	}
	return int(checkInterval / rtInterval), nil
}

// NewRunnerWithWatermark creates a runner func for CheckWithWatermark
func NewRunnerWithWatermark(config RunnerConfig, watermarkChan <-chan *watermark.Signal, signalHandler ShouldRunOnWatermark) (func(), error) {
	r := &runnerWithWatermark{
		RunnerConfig:   config,
		checkRunTicker: time.NewTicker,
		stopTicker: func(t *time.Ticker) {
			t.Stop()
		},
		watermarkChan:        watermarkChan,
		shouldRunOnWatermark: signalHandler,
	}

	return r.run, nil
}

// run performs runs for CheckWithWatermark checks
func (r *runnerWithWatermark) run() {
	ticker := time.NewTicker(r.CheckInterval)
	var lastRun time.Time

	for {
		select {
		case <-ticker.C:
			log.Info("Running watermark check due to ticker")
			r.RunCheck(RunOptions{})
			lastRun = time.Now()
		case s := <-r.watermarkChan:
			// TODO: we need to improve the handling logic. E.g, if we have the following events
			// 12:10:10 -> ticker run
			// 12:10:10:500 -> item_count_100_full: -> signal will be ignored
			// If no event is added to the store, the next run will only take place at 12:10:20
			// idea: If item_count_100_full is received, we schedule a run for the following second given that the next event
			// added to the store will expire an old event entry
			if r.shouldRunOnWatermark(s) && time.Since(lastRun) > time.Second {
				log.Infof("Running watermark check due to watermark signal: %s", s.SignalType.String())
				r.RunCheck(RunOptions{})
				lastRun = time.Now()
			}
			log.Infof("Received watermark signal: %s. Ignoring it due to cooldown window (1s)", s.SignalType.String())
		case _, ok := <-r.ExitChan:
			log.Info("Stopping watermark runner")
			if !ok {
				return
			}
		}
	}
}
