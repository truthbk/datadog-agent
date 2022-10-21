//go:build linux_bpf
// +build linux_bpf

package main

import (
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	manager "github.com/DataDog/ebpf-manager"
)

func guessOffsets() ([]manager.ConstantEditor, error) {
	cfg := config.New()
	buf, err := netebpf.ReadOffsetBPFModule(cfg.BPFDir, cfg.BPFDebug)
	if err != nil {
		return nil, err
	}
	defer buf.Close()

	return tracer.RunOffsetGuessing(cfg, buf)
}
