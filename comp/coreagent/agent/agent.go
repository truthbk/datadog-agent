// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"go.uber.org/fx"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"

	"github.com/DataDog/datadog-agent/cmd/agent/api"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/cmd/agent/common/misconfig"
	"github.com/DataDog/datadog-agent/cmd/agent/gui"
	"github.com/DataDog/datadog-agent/cmd/manager"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/coreagent/agent/internal/clcrunnerapi"
	"github.com/DataDog/datadog-agent/comp/coreagent/internal"
	jmxlog "github.com/DataDog/datadog-agent/comp/jmx/log"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/api/healthprobe"
	"github.com/DataDog/datadog-agent/pkg/cloudfoundry/containertagger"
	"github.com/DataDog/datadog-agent/pkg/collector"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/embed/jmx"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
	remoteconfig "github.com/DataDog/datadog-agent/pkg/config/remote/service"
	"github.com/DataDog/datadog-agent/pkg/dogstatsd"
	"github.com/DataDog/datadog-agent/pkg/forwarder"
	"github.com/DataDog/datadog-agent/pkg/logs"
	"github.com/DataDog/datadog-agent/pkg/metadata"
	"github.com/DataDog/datadog-agent/pkg/metadata/host"
	"github.com/DataDog/datadog-agent/pkg/metadata/inventories"
	"github.com/DataDog/datadog-agent/pkg/netflow"
	"github.com/DataDog/datadog-agent/pkg/otlp"
	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/datadog-agent/pkg/snmp/traps"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/cloudproviders"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/DataDog/datadog-agent/pkg/version"
)

type agent struct {
	params internal.BundleParams
	config config.Component
	log    log.Component

	// demux is the demultiplexer, started in start method and later stopped.
	demux *aggregator.AgentDemultiplexer
}

type dependencies struct {
	fx.In

	Lc     fx.Lifecycle
	Params internal.BundleParams

	Log    log.Component
	JmxLog jmxlog.Component
	Config config.Component
}

// newAgent creates a new agent component, which will start and stop based on
// the fx Lifecycle.
func newAgent(deps dependencies) (Component, error) {
	a := &agent{
		config: deps.Config,
		log:    deps.Log,
	}

	deps.Lc.Append(fx.Hook{OnStart: a.start, OnStop: a.stop})

	return a, nil
}

func (a *agent) start(ctx context.Context) error {
	var err error

	// Main context passed to components
	// TODO: eliminate these
	common.MainCtx, common.MainCtxCancel = context.WithCancel(context.Background())

	if flavor.GetFlavor() == flavor.IotAgent {
		a.log.Infof("Starting Datadog IoT Agent v%v", version.AgentVersion)
	} else {
		a.log.Infof("Starting Datadog Agent v%v", version.AgentVersion)
	}

	if err := util.SetupCoreDump(); err != nil {
		a.log.Warnf("Can't setup core dumps: %v, core dumps might not be available after a crash", err)
	}

	if v := a.config.GetBool("internal_profiling.capture_all_allocations"); v {
		runtime.MemProfileRate = 1
		a.log.Infof("MemProfileRate set to 1, capturing every single memory allocation!")
	}

	// init settings that can be changed at runtime
	if err := initRuntimeSettings(); err != nil {
		a.log.Warnf("Can't initiliaze the runtime settings: %v", err)
	}

	// Setup Internal Profiling
	common.SetupInternalProfiling()

	// Setup expvar server
	telemetryHandler := telemetry.Handler()
	expvarPort := a.config.GetString("expvar_port")
	if a.config.GetBool("telemetry.enabled") {
		http.Handle("/telemetry", telemetryHandler)
	}
	go func() {
		common.ExpvarServer = &http.Server{
			Addr:    fmt.Sprintf("127.0.0.1:%s", expvarPort),
			Handler: http.DefaultServeMux,
		}
		if err := common.ExpvarServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Errorf("Error creating expvar server on %v: %v", common.ExpvarServer.Addr, err)
		}
	}()

	// Setup healthcheck port
	healthPort := a.config.GetInt("health_port")
	if healthPort > 0 {
		err := healthprobe.Serve(common.MainCtx, healthPort)
		if err != nil {
			return a.log.Errorf("Error starting health port, exiting: %v", err)
		}
		a.log.Debugf("Health check listening on port %d", healthPort)
	}

	if a.params.PidfilePath != "" {
		err = pidfile.WritePID(a.params.PidfilePath)
		if err != nil {
			return a.log.Errorf("Error while writing PID file, exiting: %v", err)
		}
		a.log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), a.params.PidfilePath)
	}

	err = manager.ConfigureAutoExit(common.MainCtx)
	if err != nil {
		return a.log.Errorf("Unable to configure auto-exit, err: %v", err)
	}

	hostnameDetected, err := hostname.Get(context.TODO())
	if err != nil {
		return a.log.Errorf("Error while getting hostname, exiting: %v", err)
	}
	a.log.Infof("Hostname is: %s", hostnameDetected)

	// HACK: init host metadata module (CPU) early to avoid any
	//       COM threading model conflict with the python checks
	err = host.InitHostMetadata()
	if err != nil {
		a.log.Errorf("Unable to initialize host metadata: %v", err)
	}

	// start remote configuration management
	var configService *remoteconfig.Service
	if a.config.GetBool("remote_configuration.enabled") {
		configService, err = remoteconfig.NewService()
		if err != nil {
			a.log.Errorf("Failed to initialize config management service: %s", err)
		} else if err := configService.Start(context.Background()); err != nil {
			a.log.Errorf("Failed to start config management service: %s", err)
		}
	}

	// create and setup the Autoconfig instance
	common.LoadComponents(common.MainCtx, a.config.GetString("confd_path"))

	// start the cloudfoundry container tagger
	if pkgconfig.IsFeaturePresent(pkgconfig.CloudFoundry) && !a.config.GetBool("cloud_foundry_buildpack") {
		containerTagger, err := containertagger.NewContainerTagger()
		if err != nil {
			a.log.Errorf("Failed to create Cloud Foundry container tagger: %v", err)
		} else {
			containerTagger.Start(common.MainCtx)
		}
	}

	// start the cmd HTTP server
	if err = api.StartServer(configService); err != nil {
		return a.log.Errorf("Error while starting api server, exiting: %v", err)
	}

	// start clc runner server
	// only start when the cluster agent is enabled and a cluster check runner host is enabled
	if a.config.GetBool("cluster_agent.enabled") && a.config.GetBool("clc_runner_enabled") {
		if err = clcrunnerapi.StartCLCRunnerServer(map[string]http.Handler{
			"/telemetry": telemetryHandler,
		}); err != nil {
			return a.log.Errorf("Error while starting clc runner api server, exiting: %v", err)
		}
	}

	// start the GUI server
	guiPort := a.config.GetString("GUI_port")
	if guiPort == "-1" {
		a.log.Infof("GUI server port -1 specified: not starting the GUI.")
	} else if err = gui.StartGUIServer(guiPort); err != nil {
		a.log.Errorf("Error while starting GUI: %v", err)
	}

	// setup the forwarder
	keysPerDomain, err := pkgconfig.GetMultipleEndpoints()
	if err != nil {
		a.log.Error("Misconfiguration of agent endpoints: ", err)
	}

	forwarderOpts := forwarder.NewOptions(keysPerDomain)
	// Enable core agent specific features like persistence-to-disk
	forwarderOpts.EnabledFeatures = forwarder.SetFeature(forwarderOpts.EnabledFeatures, forwarder.CoreFeatures)
	opts := aggregator.DefaultAgentDemultiplexerOptions(forwarderOpts)
	opts.EnableNoAggregationPipeline = a.config.GetBool("dogstatsd_no_aggregation_pipeline")
	opts.UseContainerLifecycleForwarder = a.config.GetBool("container_lifecycle.enabled")
	a.demux = aggregator.InitAndStartAgentDemultiplexer(opts, hostnameDetected)

	// Setup stats telemetry handler
	if sender, err := a.demux.GetDefaultSender(); err == nil {
		telemetry.RegisterStatsSender(sender)
	}

	// Start OTLP intake
	otlpEnabled := otlp.IsEnabled(pkgconfig.Datadog) // TODO: better approach?
	inventories.SetAgentMetadata(inventories.AgentOTLPEnabled, otlpEnabled)
	if otlpEnabled {
		var err error
		common.OTLP, err = otlp.BuildAndStart(common.MainCtx, pkgconfig.Datadog, // TODO: hmm
			a.demux.Serializer())
		if err != nil {
			a.log.Errorf("Could not start OTLP: %s", err)
		} else {
			a.log.Debug("OTLP pipeline started")
		}
	}

	// Start SNMP trap server
	if traps.IsEnabled() {
		err = traps.StartServer(hostnameDetected, a.demux)
		if err != nil {
			a.log.Errorf("Failed to start snmp-traps server: %s", err)
		}
	}

	if err = common.SetupSystemProbeConfig(a.params.SysProbeConfFilePath); err != nil {
		a.log.Infof("System probe config not found, disabling pulling system probe info in the status page: %v", err)
	}

	// Detect Cloud Provider
	go cloudproviders.DetectCloudProvider(context.Background())

	// Append version and timestamp to version history log file if this Agent is different than the last run version
	util.LogVersionHistory()

	// Set up check collector
	common.AC.AddScheduler("check", collector.InitCheckScheduler(common.Coll), true)
	common.Coll.Start()

	a.demux.AddAgentStartupTelemetry(version.AgentVersion)

	// start dogstatsd
	if a.config.GetBool("use_dogstatsd") {
		var err error
		common.DSD, err = dogstatsd.NewServer(a.demux, false)
		if err != nil {
			a.log.Errorf("Could not start dogstatsd: %s", err)
		} else {
			a.log.Debugf("dogstatsd started")
		}
	}

	// start logs-agent.  This must happen after AutoConfig is set up (via common.LoadComponents)
	if a.config.GetBool("logs_enabled") || a.config.GetBool("log_enabled") {
		if a.config.GetBool("log_enabled") {
			a.log.Warn(`"log_enabled" is deprecated, use "logs_enabled" instead`)
		}
		if _, err := logs.Start(common.AC); err != nil {
			a.log.Error("Could not start logs-agent: ", err)
		}
	} else {
		a.log.Info("logs-agent disabled")
	}

	// Start NetFlow server
	// This must happen after LoadComponents is set up (via common.LoadComponents).
	// netflow.StartServer uses AgentDemultiplexer, that uses ContextResolver, that uses the tagger (initialized by LoadComponents)
	if netflow.IsEnabled() {
		sender, err := a.demux.GetDefaultSender()
		if err != nil {
			a.log.Errorf("Failed to get default sender for NetFlow server: %s", err)
		} else {
			err = netflow.StartServer(sender)
			if err != nil {
				a.log.Errorf("Failed to start NetFlow server: %s", err)
			}
		}
	}

	// load and run all configs in AD
	common.AC.LoadAndRun(common.MainCtx)

	// check for common misconfigurations and report them to log
	misconfig.ToLog(misconfig.CoreAgent)

	// setup the metadata collector
	common.MetadataScheduler = metadata.NewScheduler(a.demux)
	if err := metadata.SetupMetadataCollection(common.MetadataScheduler, metadata.AllDefaultCollectors); err != nil {
		return err
	}

	if err := metadata.SetupInventories(common.MetadataScheduler, common.Coll); err != nil {
		return err
	}

	// start dependent services
	go startDependentServices()

	return nil
}

func (a *agent) stop(ctx context.Context) error {
	// retrieve the agent health before stopping the components
	// GetReadyNonBlocking has a 100ms timeout to avoid blocking
	health, err := health.GetReadyNonBlocking()
	if err != nil {
		a.log.Warnf("Agent health unknown: %s", err)
	} else if len(health.Unhealthy) > 0 {
		a.log.Warnf("Some components were unhealthy: %v", health.Unhealthy)
	}

	if common.ExpvarServer != nil {
		if err := common.ExpvarServer.Shutdown(context.Background()); err != nil {
			a.log.Errorf("Error shutting down expvar server: %v", err)
		}
	}
	if common.DSD != nil {
		common.DSD.Stop()
	}
	if common.OTLP != nil {
		common.OTLP.Stop()
	}
	if common.AC != nil {
		common.AC.Stop()
	}
	if common.MetadataScheduler != nil {
		common.MetadataScheduler.Stop()
	}
	traps.StopServer()
	netflow.StopServer()
	api.StopServer()
	clcrunnerapi.StopCLCRunnerServer()
	jmx.StopJmxfetch()

	if a.demux != nil {
		a.demux.Stop(true)
	}

	logs.Stop()
	gui.StopGUIServer()
	profiler.Stop()

	os.Remove(a.params.PidfilePath)

	// gracefully shut down any component
	common.MainCtxCancel()

	a.log.Info("See ya!")
	a.log.Flush()

	return nil
}
