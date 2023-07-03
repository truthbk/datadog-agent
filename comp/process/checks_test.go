// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package process

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/sysprobeconfig"
	"github.com/DataDog/datadog-agent/comp/process/connectionscheck"
	"github.com/DataDog/datadog-agent/comp/process/containercheck"
	"github.com/DataDog/datadog-agent/comp/process/podcheck"
	"github.com/DataDog/datadog-agent/comp/process/processcheck"
	"github.com/DataDog/datadog-agent/comp/process/processdiscoverycheck"
	"github.com/DataDog/datadog-agent/comp/process/processeventscheck"
	"github.com/DataDog/datadog-agent/comp/process/rtcontainercheck"
	"github.com/DataDog/datadog-agent/comp/process/types"
	pkgConfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func testCheck(t *testing.T, name string, coreOverrides, sysProbeOverrides map[string]interface{}, test func(t *testing.T, enabledChecks []string)) {
	t.Run(name, func(t *testing.T) {
		f, err := os.CreateTemp("", "sysprobeconfig.*.yaml")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = os.Remove(f.Name())
		})

		pkgConfig.SetFeatures(t)

		err = json.NewEncoder(f).Encode(sysProbeOverrides)
		require.NoError(t, err)

		deps := fxutil.Test[struct {
			fx.In

			M      sysprobeconfig.Component
			Checks []types.CheckComponent `group:"check"`
		}](t,
			fx.Supply(core.BundleParams{SysprobeConfigParams: sysprobeconfig.NewParams(sysprobeconfig.WithSysProbeConfFilePath(f.Name()))}),
			fx.Replace(config.MockParams{Overrides: coreOverrides}),

			connectionscheck.Module,
			containercheck.Module,
			podcheck.Module,
			processcheck.Module,
			processdiscoverycheck.Module,
			processeventscheck.Module,
			rtcontainercheck.Module,

			core.MockBundle,
		)
		fmt.Println(deps.M.AllSettings())
		enabledChecks := make([]string, 0, len(deps.Checks))
		for _, ch := range deps.Checks {
			ch := ch.Object()
			if ch.IsEnabled() {
				enabledChecks = append(enabledChecks, ch.Name())
			}
		}

		test(t, enabledChecks)
	})
}

func TestProcessDiscovery(t *testing.T) {
	// Make sure the process_discovery check can be enabled
	testCheck(t, "enabled", map[string]interface{}{
		"process_config.process_discovery.enabled": true,
	}, nil, func(t *testing.T, enabledChecks []string) {
		assert.Contains(t, enabledChecks, checks.DiscoveryCheckName)
	})

	// Make sure the process_discovery check can be disabled
	testCheck(t, "disabled", map[string]interface{}{
		"process_config.process_discovery.enabled": false,
	}, nil, func(t *testing.T, enabledChecks []string) {
		assert.NotContains(t, enabledChecks, checks.DiscoveryCheckName)
	})

	// Make sure the process and process_discovery checks are mutually exclusive
	testCheck(t, "mutual exclusion", map[string]interface{}{
		"process_config.process_discovery.enabled":  true,
		"process_config.process_collection.enabled": true,
	}, nil, func(t *testing.T, enabledChecks []string) {
		assert.Contains(t, enabledChecks, checks.ProcessCheckName)
		assert.NotContains(t, enabledChecks, checks.DiscoveryCheckName)
	})
}

func TestProcessCheck(t *testing.T) {
	testCheck(t, "disabled", map[string]interface{}{
		"process_config.process_collection.enabled": false,
	}, nil, func(t *testing.T, enabledChecks []string) {
		assert.NotContains(t, enabledChecks, checks.ProcessCheckName)
	})

	testCheck(t, "enabled", map[string]interface{}{
		"process_config.process_collection.enabled": true,
	}, nil, func(t *testing.T, enabledChecks []string) {
		assert.Contains(t, enabledChecks, checks.ProcessCheckName)
	})
}

func TestConnectionsCheck(t *testing.T) {
	testCheck(t, "enabled", nil,
		map[string]interface{}{
			"network_config.enabled":      true,
			"system_probe_config.enabled": true,
		},
		func(t *testing.T, enabledChecks []string) {
			if runtime.GOOS == "darwin" {
				assert.NotContains(t, enabledChecks, checks.ConnectionsCheckName)
			} else {
				t.Skip()
				assert.Contains(t, enabledChecks, checks.ConnectionsCheckName)
			}
		},
	)

	testCheck(t, "disabled", nil,
		map[string]interface{}{
			"network_config.enabled": false,
		},
		func(t *testing.T, enabledChecks []string) {
			assert.NotContains(t, enabledChecks, checks.ConnectionsCheckName)
		},
	)
}
