// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package processes

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	checkName = "live_processes"
)

func init() {
	core.RegisterCheck(checkName, CheckFactory)
}

// Config holds the container_image check configuration
type Config struct {
	ChunkSize      int `yaml:"chunk_size"`
	RefreshSeconds int `yaml:"interval_s"`
}

type configValueRange struct {
	min      int
	max      int
	default_ int
}

var /* const */ (
	chunkSizeValueRange = &configValueRange{
		min:      1,
		max:      200,
		default_: 100,
	}

	periodicRefreshSecondsValueRange = &configValueRange{
		min:      2,  // 2s
		max:      60, // 60s
		default_: 10, // 10s
	}
)

func validateValue(val *int, range_ *configValueRange) {
	if *val == 0 {
		*val = range_.default_
	} else if *val < range_.min {
		*val = range_.min
	} else if *val > range_.max {
		*val = range_.max
	}
}

func (c *Config) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}

	validateValue(&c.ChunkSize, chunkSizeValueRange)
	validateValue(&c.RefreshSeconds, periodicRefreshSecondsValueRange)

	return nil
}

// Check reports Live Processes
type Check struct {
	core.CheckBase

	instance  *Config
	processor *processor
	stopCh    chan struct{}
}

// CheckFactory registers the live_processes check
func CheckFactory() check.Check {
	log.Info("REGISTERING LP CHECK")
	return &Check{
		CheckBase: core.NewCheckBase(checkName),
		instance:  &Config{},
		stopCh:    make(chan struct{}),
	}
}

// Configure parses the check configuration and initializes the live_processes check
func (c *Check) Configure(integrationConfigDigest uint64, config, initConfig integration.Data, source string) error {
	log.Info("CONFIGURING LIVE PROCESS CHECK")
	if err := c.CommonConfigure(integrationConfigDigest, initConfig, config, source); err != nil {
		return err
	}

	if err := c.instance.Parse(config); err != nil {
		return err
	}

	sender, err := c.GetSender()
	if err != nil {
		return err
	}

	c.processor = newProcessor(sender, c.instance.ChunkSize, time.Minute)

	return nil
}

func printProcesses(procs map[int32]*procutil.Process) {
	log.Info("COLLECTED PROCESSES: ")
	for _, p := range procs {
		log.Info(fmt.Sprintf("%d: %s", p.Pid, strings.Join(p.Cmdline, " ")))
	}
}

// Run starts the container_image check
func (c *Check) Run() error {
	log.Infof("Starting long-running check %q", c.ID())
	defer log.Infof("Shutting down long-running check %q", c.ID())

	log.Info("RUNNING LIVE PROCESS CHECK")
	// TODO: consider instantiating an instance of the Process Check here that already wraps all the collection logic
	// and outputs the message to be sent to our backend
	// TODO: figure out how to pass global Datadog config to the check from here

	refreshTicker := time.NewTicker(time.Duration(c.instance.RefreshSeconds) * time.Second)
	// TODO: Do we need to perform period collections here or can this be handled on the collector side?
	for {
		select {
		case <-refreshTicker.C:
			c.processor.collectProcesses()
		case <-c.stopCh:
			c.processor.stop()
			return nil
		}
	}
	return nil
}

// Stop stops the container_image check
func (c *Check) Stop() {
	close(c.stopCh)
}

// Interval returns 0. It makes container_image a long-running check
func (c *Check) Interval() time.Duration {
	return 0
}
