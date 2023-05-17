// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package agenttest

import (
	"github.com/stretchr/testify/assert"
)

func AssertRunningChecks(a *assert.Assertions, status map[string]any) bool {
	v, ok := status["runnerStats"]
	if !a.True(ok, "status should have runnerStats key") {
		return false
	}

	runnerStats := v.(map[string]any)
	v, ok = runnerStats["Checks"]
	if !a.True(ok, "runnerStats should have Checks key") {
		return false
	}

	return true
}

