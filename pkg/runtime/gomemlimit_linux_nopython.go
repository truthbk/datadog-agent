// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && !python

package runtime

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/config"
)

func RunMemoryLimiter(c context.Context) error {
	return NewStaticMemoryLimiter(config.Datadog.GetFloat64("gomemlimit_pct"), config.IsContainerized()).Run(c)
}
