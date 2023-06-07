// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package telemetry

import (
	"net/http"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// team: agent-shared-components

// Component is the component type.
type Component interface {
	Handler() http.Handler
	Reset()

	NewCounter(subsystem, name string, tags []string, help string) Counter
	NewCounterWithOpts(subsystem, name string, tags []string, help string, opts Options) Counter

	NewSimpleCounter(subsystem, name, help string) SimpleCounter
	NewSimpleCounterWithOpts(subsystem, name, help string, opts Options) SimpleCounter

	NewGauge(subsystem, name string, tags []string, help string) Gauge
	NewGaugeWithOpts(subsystem, name string, tags []string, help string, opts Options) Gauge

	NewSimpleGauge(subsystem, name, help string) SimpleGauge
	NewSimpleGaugeWithOpts(subsystem, name, help string, opts Options) SimpleGauge

	NewHistogram(subsystem, name string, tags []string, help string, buckets []float64) Histogram
	NewHistogramWithOpts(subsystem, name string, tags []string, help string, buckets []float64, opts Options) Histogram

	NewSimpleHistogram(subsystem, name, help string, buckets []float64) SimpleHistogram
	NewSimpleHistogramWithOpts(subsystem, name, help string, buckets []float64, opts Options) SimpleHistogram
}

// Mock implements mock-specific methods.
type Mock interface {
	Component
}

// Module defines the fx options for this component.
var Module = fxutil.Component(
	fx.Provide(newTelemetry),
)

// MockModule defines the fx options for the mock component.
// var MockModule = fxutil.Component(
// 	fx.Provide(newMock),
// )
