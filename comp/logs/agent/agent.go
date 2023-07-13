// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	configComponent "github.com/DataDog/datadog-agent/comp/core/config"
	logComponent "github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	pkgConfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/auditor"
	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/launchers"
	"github.com/DataDog/datadog-agent/pkg/logs/metrics"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/status"
	"github.com/DataDog/datadog-agent/pkg/logs/tailers"
	"github.com/DataDog/datadog-agent/pkg/metadata/inventories"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
	"go.uber.org/atomic"
	"go.uber.org/fx"
)

const (
	// key used to display a warning message on the agent status
	invalidProcessingRules = "invalid_global_processing_rules"
	invalidEndpoints       = "invalid_endpoints"
	intakeTrackType        = "logs"

	// AgentJSONIntakeProtocol agent json protocol
	AgentJSONIntakeProtocol = "agent-json"

	// Log messages
	multiLineWarning = "multi_line processing rules are not supported as global processing rules."
)

type dependencies struct {
	fx.In

	Lc     fx.Lifecycle
	Log    logComponent.Component
	Config configComponent.Component
}

type logsAgentState struct {
	sources                   *sources.LogSources
	services                  *service.Services
	endpoints                 *config.Endpoints
	tracker                   *tailers.TailerTracker
	schedulers                *schedulers.Schedulers
	auditor                   auditor.Auditor
	destinationsCtx           *client.DestinationsContext
	pipelineProvider          pipeline.Provider
	launchers                 *launchers.Launchers
	health                    *health.Handle
	diagnosticMessageReceiver *diagnostic.BufferedMessageReceiver
}

// Agent represents the data pipeline that collects, decodes,
// processes and sends logs to the backend.  See the package README for
// a description of its operation.
type agent struct {
	log    logComponent.Component
	config pkgConfig.ConfigReader

	state *logsAgentState

	// started is true if the agent has ever been started
	started *atomic.Bool
}

func newLogsAgent(deps dependencies) Component {
	logsAgent := &agent{log: deps.Log, config: deps.Config, started: atomic.NewBool(false)}
	deps.Lc.Append(fx.Hook{
		OnStart: logsAgent.start,
		OnStop:  logsAgent.stop,
	})
	return logsAgent
}

func (a *agent) start(context.Context) error {
	if a.config.GetBool("logs_enabled") || a.config.GetBool("log_enabled") {
		if a.config.GetBool("log_enabled") {
			a.log.Warn(`"log_enabled" is deprecated, use "logs_enabled" instead`)
		}

		log.Info("Starting logs-agent...")
		err := a.createAgentState()

		if err != nil {
			a.log.Error("Could not start logs-agent: ", err)
			return err
		}

		a.startPipeline()
		a.log.Info("logs-agent started")
	} else {
		a.log.Info("logs-agent disabled")
	}

	return nil
}

func (a *agent) createAgentState() error {
	// setup the sources and the services
	sources := sources.NewLogSources()
	services := service.NewServices()
	tracker := tailers.NewTailerTracker()

	// setup the server config
	endpoints, err := buildEndpoints()

	if err != nil {
		message := fmt.Sprintf("Invalid endpoints: %v", err)
		status.AddGlobalError(invalidEndpoints, message)
		return errors.New(message)
	}
	status.CurrentTransport = status.TransportTCP
	if endpoints.UseHTTP {
		status.CurrentTransport = status.TransportHTTP
	}
	inventories.SetAgentMetadata(inventories.AgentLogsTransport, status.CurrentTransport)

	// setup global processing rules
	processingRules, err := config.GlobalProcessingRules()
	if err != nil {
		message := fmt.Sprintf("Invalid processing rules: %v", err)
		status.AddGlobalError(invalidProcessingRules, message)
		return errors.New(message)
	}

	if config.HasMultiLineRule(processingRules) {
		log.Warn(multiLineWarning)
		status.AddGlobalWarning(invalidProcessingRules, multiLineWarning)
	}

	a.state = a.NewAgentState(sources, services, tracker, processingRules, endpoints)
	return nil
}

// Start starts all the elements of the data pipeline
// in the right order to prevent data loss
func (a *agent) startPipeline() {
	if a.IsRunning() {
		panic("logs agent cannot be started more than once")
	}
	a.started.Store(true)

	// setup the status
	status.Init(a.started, a.state.endpoints, a.state.sources, a.state.tracker, metrics.LogsExpvars)

	starter := startstop.NewStarter(
		a.state.destinationsCtx,
		a.state.auditor,
		a.state.pipelineProvider,
		a.state.diagnosticMessageReceiver,
		a.state.launchers,
		a.state.schedulers,
	)
	starter.Start()
}

func (a *agent) stop(context.Context) error {
	if !a.IsRunning() {
		log.Info("Can't stop the logs agent because it is not running")
		return nil
	}
	log.Info("Stopping logs-agent")

	status.Clear()

	stopper := startstop.NewSerialStopper(
		a.state.schedulers,
		a.state.launchers,
		a.state.pipelineProvider,
		a.state.auditor,
		a.state.destinationsCtx,
		a.state.diagnosticMessageReceiver,
	)

	// This will try to stop everything in order, including the potentially blocking
	// parts like the sender. After StopTimeout it will just stop the last part of the
	// pipeline, disconnecting it from the auditor, to make sure that the pipeline is
	// flushed before stopping.
	// TODO: Add this feature in the stopper.
	c := make(chan struct{})
	go func() {
		stopper.Stop()
		close(c)
	}()
	timeout := time.Duration(a.config.GetInt("logs_config.stop_grace_period")) * time.Second
	select {
	case <-c:
	case <-time.After(timeout):
		log.Info("Timed out when stopping logs-agent, forcing it to stop now")
		// We force all destinations to read/flush all the messages they get without
		// trying to write to the network.
		a.state.destinationsCtx.Stop()
		// Wait again for the stopper to complete.
		// In some situation, the stopper unfortunately never succeed to complete,
		// we've already reached the grace period, give it some more seconds and
		// then force quit.
		timeout := time.NewTimer(5 * time.Second)
		select {
		case <-c:
		case <-timeout.C:
			log.Warn("Force close of the Logs Agent, dumping the Go routines.")
			if stack, err := util.GetGoRoutinesDump(); err != nil {
				log.Warnf("can't get the Go routines dump: %s\n", err)
			} else {
				log.Warn(stack)
			}
		}
	}
	log.Info("logs-agent stopped")
	return nil
}

// AddScheduler adds the given scheduler to the agent.
func (a *agent) AddScheduler(scheduler schedulers.Scheduler) {
	a.state.schedulers.AddScheduler(scheduler)
}

func (a *agent) IsRunning() bool {
	return a.state != nil && a.started.Load()
}

func (a *agent) GetMessageReceiver() *diagnostic.BufferedMessageReceiver {
	if !a.IsRunning() {
		log.Info("Can't get message receiver because the logs agent is not running")
		return nil
	}
	return a.state.diagnosticMessageReceiver
}

// Flush flushes synchronously the running instance of the Logs Agent.
// Use a WithTimeout context in order to have a flush that can be cancelled.
func (a *agent) Flush(ctx context.Context) {
	if !a.IsRunning() {
		log.Info("Can't flush the logs agent because it is not running")
		return
	}

	log.Info("Triggering a flush in the logs-agent")
	a.state.pipelineProvider.Flush(ctx)
	log.Debug("Flush in the logs-agent done.")
}
