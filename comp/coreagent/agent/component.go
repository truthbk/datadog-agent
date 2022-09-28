// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package agent is a temporary component to contain the "core agent".  This component
// will be broken down into smaller pieces as compontentization continues.
//
// This component has no API, but implements agent startup and shutdown using hooks.
package agent

import (
	"go.uber.org/fx"
)

// team: agent-shared-components

const componentName = "comp/coreagent/agent"

// Component is the component type.
type Component interface {
}

// Module defines the fx options for this component.
var Module fx.Option = fx.Module(
	componentName,

	fx.Provide(newAgent),
)
