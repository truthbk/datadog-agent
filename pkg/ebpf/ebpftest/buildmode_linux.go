// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ebpftest

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"

	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

var kv = kernel.MustHostVersion()
var fentrySupported bool

func init() {
	fentrySupported = runtime.GOARCH == "amd64" && features.HaveProgramType(ebpf.Tracing) == nil
}

func SupportedBuildModes() []BuildMode {
	modes := []BuildMode{Prebuilt, RuntimeCompiled, CORE}
	if fentrySupported {
		modes = append(modes, Fentry)
	}
	return modes
}

func TestBuildModes(t *testing.T, modes []BuildMode, name string, fn func(t *testing.T)) {
	for _, mode := range modes {
		TestBuildMode(t, mode, name, fn)
	}
}

func TestBuildMode(t *testing.T, mode BuildMode, name string, fn func(t *testing.T)) {
	t.Run(mode.String(), func(t *testing.T) {
		for k, v := range mode.Env() {
			t.Setenv(k, v)
		}
		if name != "" {
			t.Run(name, fn)
		} else {
			fn(t)
		}
	})
}
