// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package coreagent is a temporary bundle to contain the "core agent".  This component
// will be broken down into smaller pieces as compontentization continues.
//
// Including `coreagent.Module` in an App will automatically start the agent.
//
// This bundle depends on comp/core and comp/jmx.
package coreagent

import (
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/coreagent/agent"
	"github.com/DataDog/datadog-agent/comp/coreagent/internal"
)

// team: agent-shared-components

const componentName = "comp/coreagent"

// BundleParams defines the parameters for this bundle.
type BundleParams = internal.BundleParams

// Bundle defines the fx options for this bundle.
var Bundle = fx.Module(
	componentName,

	agent.Module,

	// require the agent component, causing it to start
	fx.Invoke(func(_ agent.Component) {}),
)
