// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package patch

import (
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	"k8s.io/client-go/kubernetes"
)

// ControllerContext holds necessary context for the patch controller
type ControllerContext struct {
	IsLeaderFunc func() bool
	Client       kubernetes.Interface
	StopCh       chan struct{}
}

// StartControllers starts the patch controllers
func StartControllers(ctx ControllerContext) {
	if !config.Datadog.GetBool("admission_controller.auto_instrumentation.remote_config.enabled") {
		log.Info("Remote-config-based auto instrumentation is disabled")
		return
	}
	log.Info("Starting patch controllers")

	rp := newRequestProvider(ctx.IsLeaderFunc)
	dp := newDeployPatcher(ctx.Client, ctx.IsLeaderFunc, rp)
	go rp.start(ctx.StopCh)
	go dp.start(ctx.StopCh)
}
