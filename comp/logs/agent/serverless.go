// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package agent

import (
	"context"

	logComponent "github.com/DataDog/datadog-agent/comp/core/log"
	pkgConfig "github.com/DataDog/datadog-agent/pkg/config"
	"go.uber.org/atomic"
)

func NewServerlessLogsAgent() ServerlessLogsAgent {
	logsAgent := &agent{log: logComponent.NewTemporaryLoggerWithoutInit(), config: pkgConfig.Datadog, started: atomic.NewBool(false)}
	return logsAgent
}

func (a *agent) Start() error {
	err := a.setupAgent()
	if err != nil {
		a.log.Error("Could not start logs-agent: ", err)
		return err
	}

	a.startPipeline()
	a.log.Info("logs-agent started")
	return nil
}

func (a *agent) Stop() {
	_ = a.stop(context.TODO())
}

// Flush flushes synchronously the running instance of the Logs Agent.
// Use a WithTimeout context in order to have a flush that can be cancelled.
func (a *agent) Flush(ctx context.Context) {
	a.log.Info("Triggering a flush in the logs-agent")
	a.pipelineProvider.Flush(ctx)
	a.log.Debug("Flush in the logs-agent done.")
}
