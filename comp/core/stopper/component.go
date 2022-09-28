// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package stopper implements a component that will shutdown a running Fx App
// on receipt of SIGINT or SIGTERM or of an explicit stop signal.
//
// During the componentization process, this component also handles
// cmd/agent/common/signals.Stopper and ErrorStopper.
//
// The component registers for signals if BundleParams#StopOnSignals is true. In
// this case, it also ignores SIGPIPE.
package stopper

import (
	"go.uber.org/fx"
)

// team: agent-shared-components

const componentName = "comp/core/stopper"

// Component is the component type.
type Component interface {
	// Stop causes the running app to stop, asynchronously.  If the error is
	// nil, then it is a "normal" stop; otherwise, it finishes with the error.
	//
	// This call is asynchronous, and will return immediately with app shutdown
	// beginning in another goroutine.
	Stop(error)
}

// Module defines the fx options for this component.
var Module fx.Option = fx.Module(
	componentName,

	fx.Provide(newStopper),

	// always require the component, so that it can register for signals
	fx.Invoke(func(Component) {}),
)
