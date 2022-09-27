// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package ebpf

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
)

// ReadTracerBPFModule from the asset file
func ReadTracerBPFModule(bpfDir string, debug bool) (bytecode.AssetReader, error) {
	return ReadBPFModule(bpfDir, "tracer", debug)
}

// ReadHTTPModule from the asset file
func ReadHTTPModule(bpfDir string, debug bool) (bytecode.AssetReader, error) {
	return ReadBPFModule(bpfDir, "http", debug)
}

// ReadDNSModule from the asset file
func ReadDNSModule(bpfDir string, debug bool) (bytecode.AssetReader, error) {
	return ReadBPFModule(bpfDir, "dns", debug)
}

// ReadOffsetBPFModule from the asset file
func ReadOffsetBPFModule(bpfDir string, debug bool) (bytecode.AssetReader, error) {
	return ReadBPFModule(bpfDir, "offset-guess", debug)
}

// ReadBPFModule reads the named asset file
func ReadBPFModule(dir string, base string, debug bool) (bytecode.AssetReader, error) {
	file := fmt.Sprintf("%s.o", base)
	if debug {
		file = fmt.Sprintf("%s-debug.o", base)
	}

	ebpfReader, err := bytecode.GetReader(dir, file)
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	return ebpfReader, nil
}
