// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package telemetry

// SimpleHistogram tracks how many times something is happening.
type SimpleHistogram interface {
	// Observe the value to the Histogram value.
	Observe(value float64)
}
