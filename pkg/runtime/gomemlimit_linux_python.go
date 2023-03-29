// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && python

package runtime

import (
	"context"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/cgroups"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const minMemLimtPct = 0.20

func RunMemoryLimiter(configNS string, c context.Context) error {
	if !config.IsPythonMemoryMonitoringEnabled() {
		log.Infof("Memory limiter not running as Python memory monitoring is disabled")
		return nil
	}

	limiter, err := NewDynamicMemoryLimiter(
		time.Duration(config.Datadog.GetFloat64(config.NSKey(configNS, "go_dynamic_memlimit_interval_seconds")))*time.Second,
		config.IsContainerized(),
		minMemLimtPct,
		func(cgroups.MemoryStats) uint64 {
			return pythonMemoryInuse.Load()
		})
	if err != nil {
		return nil
	}

	return limiter.Run(c)
}
