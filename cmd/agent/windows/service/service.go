// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows
// +build windows

package service

import (
	"fmt"
	"time"

	"go.uber.org/fx"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/stopper"
	"github.com/DataDog/datadog-agent/comp/coreagent"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var elog debug.Log

type agentWindowsService struct{}

// Execute sets up the configuration and runs the Agent as a Windows service
func (m *agentWindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	if err := common.CheckAndUpgradeConfig(); err != nil {
		elog.Warning(0x80000002, err.Error())
		// continue running with what we have.
	}

	// waitForStop listens for a message indicating the service should stop, and stops
	// the agent with comp/core/stopper.
	waitForStop := func(stopper stopper.Component) {
		const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
		elog.Info(0x40000003, config.ServiceName)
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

		// begin listening for requests on r
		go func() {
		loop:
			for {
				select {
				case c := <-r:
					switch c.Cmd {
					case svc.Interrogate:
						changes <- c.CurrentStatus
						// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
						time.Sleep(100 * time.Millisecond)
						changes <- c.CurrentStatus
					case svc.Stop:
						log.Info("Received stop message from service control manager")
						elog.Info(0x4000000c, config.ServiceName)
						break loop
					case svc.PreShutdown:
						log.Info("Received pre shutdown message from service control manager")
						elog.Info(0x40000010, config.ServiceName)
						break loop
					case svc.Shutdown:
						log.Info("Received shutdown message from service control manager")
						elog.Info(0x4000000d, config.ServiceName)
						break loop
					default:
						log.Warnf("unexpected control request #%d", c)
						elog.Error(0xc0000009, fmt.Sprint(c.Cmd))
					}
				}
			}
			elog.Info(0x4000000d, config.ServiceName)
			log.Infof("Initiating service shutdown")
			changes <- svc.Status{State: svc.StopPending}
			stopper.Stop(nil)
		}()
	}

	// build an app very similar to that used in `agent run`, with default values for
	// command-line flags, and using waitForStop to handle stopping when instructed
	err := fxutil.Run(
		fx.Supply(core.BundleParams{
			ConfFilePath:      "",
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
			PidfilePath:          "",
			SysProbeConfFilePath: "",
		}),
		coreagent.Bundle,
		fx.Invoke(waitForStop),
	)

	if err != nil {
		log.Errorf("Failed to start agent %v", err)
		elog.Error(0xc000000B, err.Error())
		errno = 1 // indicates non-successful return from handler.
		changes <- svc.Status{State: svc.Stopped}
		return
	}

	changes <- svc.Status{State: svc.Stopped}
	return
}

// RunService runs the Agent as a Windows service
func RunService(isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(config.ServiceName)
	} else {
		elog, err = eventlog.Open(config.ServiceName)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	elog.Info(0x40000007, config.ServiceName)
	run := svc.Run

	err = run(config.ServiceName, &agentWindowsService{})
	if err != nil {
		elog.Error(0xc0000008, err.Error())
		return
	}
	elog.Info(0x40000004, config.ServiceName)
}
