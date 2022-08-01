// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux && !windows
// +build !linux,!windows

package statsd

import (
	"fmt"

	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
)

func findAddr(conf *config.Config) (string, error) {
	return "", fmt.Errorf("unsupported platform")
}
