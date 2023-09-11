// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package ebpf holds ebpf related files
package ebpf

import (
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/security/ebpf/probes"
)

// NewDefaultOptions returns a new instance of the default runtime security manager options
func NewDefaultOptions() manager.Options {
	return manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		DefaultPerfRingBufferSize: probes.EventsPerfRingBufferSize,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},
	}
}

// NewRuntimeSecurityManager returns a new instance of the runtime security module manager
func NewRuntimeSecurityManager(supportsRingBuffers, useFentry bool) *manager.Manager {
	manager := &manager.Manager{
		Probes: probes.AllProbes(useFentry),
		Maps:   probes.AllMaps(),
	}
	if supportsRingBuffers {
		manager.RingBuffers = probes.AllRingBuffers()
	} else {
		manager.PerfMaps = probes.AllPerfMaps()
	}
	return manager
}
