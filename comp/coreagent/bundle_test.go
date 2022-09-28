// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package coreagent

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/coreagent/agent"
	"github.com/DataDog/datadog-agent/comp/jmx"
)

func TestBundleDependencies(t *testing.T) {
	require.NoError(t, fx.ValidateApp(
		// instantiate the agent
		fx.Invoke(func(agent.Component) {}),

		fx.Supply(core.BundleParams{}),
		core.Bundle,

		fx.Supply(jmx.BundleParams{}),
		jmx.Bundle,

		fx.Supply(BundleParams{}),
		Bundle))
}
