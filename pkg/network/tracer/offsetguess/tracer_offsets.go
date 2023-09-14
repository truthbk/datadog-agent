// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"fmt"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

// Tracer is of the offset results of the tracer offset guesser
var Tracer tracerOffsets

type tracerOffsets struct {
	offsets []manager.ConstantEditor
	err     error
}

func boolConst(name string, value bool) manager.ConstantEditor {
	c := manager.ConstantEditor{
		Name:  name,
		Value: uint64(1),
	}
	if !value {
		c.Value = uint64(0)
	}

	return c
}

func (o *tracerOffsets) Offsets(cfg *config.Config) ([]manager.ConstantEditor, error) {
	fromConfig := func(c *config.Config, offsets []manager.ConstantEditor) []manager.ConstantEditor {
		var foundTCP, foundUDP bool
		for o := range offsets {
			switch offsets[o].Name {
			case "tcpv6_enabled":
				offsets[o] = boolConst("tcpv6_enabled", c.CollectTCPv6Conns)
				foundTCP = true
			case "udpv6_enabled":
				offsets[o] = boolConst("udpv6_enabled", c.CollectUDPv6Conns)
				foundUDP = true
			}
			if foundTCP && foundUDP {
				break
			}
		}
		if !foundTCP {
			offsets = append(offsets, boolConst("tcpv6_enabled", c.CollectTCPv6Conns))
		}
		if !foundUDP {
			offsets = append(offsets, boolConst("udpv6_enabled", c.CollectUDPv6Conns))
		}

		return offsets
	}

	if o.err != nil {
		return nil, o.err
	}

	if cfg.CollectUDPv6Conns {
		kv, err := kernel.HostVersion()
		if err != nil {
			return nil, err
		}

		if kv >= kernel.VersionCode(5, 18, 0) {
			_cfg := *cfg
			_cfg.CollectUDPv6Conns = false
			cfg = &_cfg
		}
	}

	if len(o.offsets) > 0 {
		// already run
		return fromConfig(cfg, o.offsets), o.err
	}

	offsetBuf, err := netebpf.ReadOffsetBPFModule(cfg.BPFDir, cfg.BPFDebug)
	if err != nil {
		o.err = fmt.Errorf("could not read offset bpf module: %s", err)
		return nil, o.err
	}
	defer offsetBuf.Close()

	o.offsets, o.err = RunOffsetGuessing(cfg, offsetBuf, NewTracerOffsetGuesser)
	return fromConfig(cfg, o.offsets), o.err
}

func (o *tracerOffsets) Reset() {
	o.err = nil
	o.offsets = nil
}
