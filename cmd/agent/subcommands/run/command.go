// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package run implements 'agent run' (and deprecated 'agent start').
package run

import (
	// TODO: move these to a debugging component
	_ "expvar"         // Blank import used because this isn't directly used in this file
	_ "net/http/pprof" // Blank import used because this isn't directly used in this file

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/coreagent"
	jmxbundle "github.com/DataDog/datadog-agent/comp/jmx"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"

	// runtime init routines

	// register core checks
	// TODO: move these to collector component
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/helm"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/ksm"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/kubernetesapiserver"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/containerlifecycle"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/containers/containerd"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/containers/cri"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/containers/docker"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/containers/generic"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/embed"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/net"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/nvidia/jetson"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/snmp"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/cpu"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/disk"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/filehandles"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/memory"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/uptime"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/winkmem"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/system/winproc"
	_ "github.com/DataDog/datadog-agent/pkg/collector/corechecks/systemd"

	// register metadata providers
	// TODO: move these to metadata component
	_ "github.com/DataDog/datadog-agent/pkg/collector/metadata"
	_ "github.com/DataDog/datadog-agent/pkg/metadata"
)

// demux is shared between StartAgent and StopAgent.
var demux *aggregator.AgentDemultiplexer

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	// pidfilePath contains the value of the --pidfile flag.
	var pidfilePath string

	runE := func(*cobra.Command, []string) error {
		var stopErr error
		err := fxutil.Run(
			fx.Supply(core.BundleParams{
				ConfFilePath:      globalParams.ConfFilePath,
				ConfigLoadSecrets: true,
				StopOnSignals:     true,
				StopErrorP:        &stopErr,
			}.LogForDaemon("CORE", "log_file", common.DefaultLogFile)),
			core.Bundle,
			fx.Supply(jmxbundle.BundleParams{
				SeparateJmxLogFile: true,
			}),
			jmxbundle.Bundle,
			fx.Supply(coreagent.BundleParams{
				PidfilePath:          pidfilePath,
				SysProbeConfFilePath: globalParams.SysProbeConfFilePath,
			}),
			coreagent.Bundle,
		)

		// return either the app-startup error or (TODO) the error from comp/core/stopper.
		if err != nil {
			return err
		}
		return stopErr
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the Agent",
		Long:  `Runs the agent in the foreground`,
		RunE:  runE,
	}
	runCmd.Flags().StringVarP(&pidfilePath, "pidfile", "p", "", "path to the pidfile")

	startCmd := &cobra.Command{
		Use:        "start",
		Deprecated: "Use \"run\" instead to start the Agent",
		RunE:       runE,
	}
	startCmd.Flags().StringVarP(&pidfilePath, "pidfile", "p", "", "path to the pidfile")

	return []*cobra.Command{startCmd, runCmd}
}
