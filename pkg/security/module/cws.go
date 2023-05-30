// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package module

import (
	"context"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/eventmonitor"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/probe/selftests"
	"github.com/DataDog/datadog-agent/pkg/security/proto/api"
	rulesmodule "github.com/DataDog/datadog-agent/pkg/security/rules"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-go/v5/statsd"
)

// CWSConsumer represents the system-probe module for the runtime security agent
type CWSConsumer struct {
	sync.RWMutex
	config       *config.RuntimeSecurityConfig
	probe        *probe.Probe
	statsdClient statsd.ClientInterface

	// internals
	wg            sync.WaitGroup
	ctx           context.Context
	cancelFnc     context.CancelFunc
	apiServer     *APIServer
	rateLimiter   *events.RateLimiter
	sendStatsChan chan chan bool
	eventSender   events.EventSender
	grpcServer    *GRPCServer
	ruleEngine    *rulesmodule.RuleEngine
}

// Init initializes the module with options
func NewCWSConsumer(evm *eventmonitor.EventMonitor, config *config.RuntimeSecurityConfig, opts Opts) (*CWSConsumer, error) {
	ctx, cancelFnc := context.WithCancel(context.Background())

	selfTester, err := selftests.NewSelfTester()
	if err != nil {
		seclog.Errorf("unable to instantiate self tests: %s", err)
	}

	c := &CWSConsumer{
		config:       config,
		probe:        evm.Probe,
		statsdClient: evm.StatsdClient,
		// internals
		ctx:           ctx,
		cancelFnc:     cancelFnc,
		apiServer:     NewAPIServer(config, evm.Probe, evm.StatsdClient, selfTester),
		rateLimiter:   events.NewRateLimiter(config, evm.StatsdClient),
		sendStatsChan: make(chan chan bool, 1),
		grpcServer:    NewGRPCServer(config.SocketPath),
	}

	// set sender
	if opts.EventSender != nil {
		c.eventSender = opts.EventSender
	} else {
		c.eventSender = c
	}

	if opts.RuleEngine {
		seclog.Infof("Instantiating CWS rule engine")
		c.ruleEngine = rulesmodule.NewRuleEngine(evm, config, evm.Probe, c.rateLimiter, c.apiServer, c.eventSender, c.statsdClient, selfTester)
		c.apiServer.SetRuleEngine(c.ruleEngine)

		if err := evm.Probe.AddCustomEventHandler(model.UnknownEventType, c); err != nil {
			return nil, err
		}
	}

	seclog.SetPatterns(config.LogPatterns...)
	seclog.SetTags(config.LogTags...)

	api.RegisterSecurityModuleServer(c.grpcServer.server, c.apiServer)

	// Activity dumps related
	evm.Probe.AddActivityDumpHandler(c)

	return c, nil
}

// ID returns id for CWS
func (c *CWSConsumer) ID() string {
	return "CWS"
}

// Start the module
func (c *CWSConsumer) Start() error {
	err := c.grpcServer.Start()
	if err != nil {
		return err
	}

	// start api server
	c.apiServer.Start(c.ctx)

	if c.ruleEngine != nil {
		if err := c.ruleEngine.Start(c.ctx, &c.wg); err != nil {
			return err
		}
	}
	seclog.Infof("runtime security started")

	return nil
}

// Close the module
func (c *CWSConsumer) Stop() {
	if c.apiServer != nil {
		c.apiServer.Stop()
	}

	if c.ruleEngine != nil {
		c.ruleEngine.Stop()
	}

	c.cancelFnc()
	c.wg.Wait()

	c.grpcServer.Stop()
}

// HandleCustomEvent is called by the probe when an event should be sent to Datadog but doesn't need evaluation
func (c *CWSConsumer) HandleCustomEvent(rule *rules.Rule, event *events.CustomEvent) {
	c.eventSender.SendEvent(rule, event, nil, "")
}

// SendEvent sends an event to the backend after checking that the rate limiter allows it for the provided rule
func (c *CWSConsumer) SendEvent(rule *rules.Rule, event events.Event, extTagsCb func() []string, service string) {
	if c.rateLimiter.Allow(rule.ID, event) {
		c.apiServer.SendEvent(rule, event, extTagsCb, service)
	} else {
		seclog.Tracef("Event on rule %s was dropped due to rate limiting", rule.ID)
	}
}

// HandleActivityDump sends an activity dump to the backend
func (c *CWSConsumer) HandleActivityDump(dump *api.ActivityDumpStreamMessage) {
	c.apiServer.SendActivityDump(dump)
}

// SendStats send stats
func (c *CWSConsumer) SendStats() {
	ackChan := make(chan bool, 1)
	c.sendStatsChan <- ackChan
	<-ackChan
}

func (c *CWSConsumer) sendStats() {
	if err := c.rateLimiter.SendStats(); err != nil {
		seclog.Debugf("failed to send rate limiter stats: %s", err)
	}
	if err := c.apiServer.SendStats(); err != nil {
		seclog.Debugf("failed to send api server stats: %s", err)
	}
}

func (c *CWSConsumer) statsSender() {
	defer c.wg.Done()

	statsTicker := time.NewTicker(c.probe.StatsPollingInterval())
	defer statsTicker.Stop()

	for {
		select {
		case ackChan := <-c.sendStatsChan:
			c.sendStats()
			ackChan <- true
		case <-statsTicker.C:
			c.sendStats()
		case <-c.ctx.Done():
			return
		}
	}
}

// UpdateEventMonitorOpts adapt the event monitor options
func UpdateEventMonitorOpts(opts *eventmonitor.Opts) {
	opts.ProbeOpts.PathResolutionEnabled = true
}
