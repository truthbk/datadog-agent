// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package run

import "github.com/cilium/ebpf/rlimit"

func removeMemlock() error {
	// Extend RLIMIT_MEMLOCK (8) size
	// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
	// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
	// using bpf(2) with BPF_MAP_CREATE.
	//
	// We are setting the limit to infinity until we have a better handle on the true requirements.
	return rlimit.RemoveMemlock()
}
