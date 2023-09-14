// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netns"

	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

type conntrackEventGenerator struct {
	udpAddr string
	udpDone func()
	udpConn net.Conn
	ns      netns.NsHandle
}

func newConntrackEventGenerator(ns netns.NsHandle) (*conntrackEventGenerator, error) {
	eg := &conntrackEventGenerator{ns: ns}

	// port 0 means we let the kernel choose a free port
	var err error
	addr := fmt.Sprintf("%s:0", listenIPv4)
	err = kernel.WithNS(eg.ns, func() error {
		eg.udpAddr, eg.udpDone, err = newUDPServer(addr)
		return err
	})
	if err != nil {
		eg.Close()
		return nil, err
	}

	return eg, nil
}

// Generate an event for offset guessing
func (e *conntrackEventGenerator) Generate(status GuessWhat, expected *ConntrackValues) error {
	if status >= GuessCtTupleOrigin &&
		status <= GuessCtNet {
		if e.udpConn != nil {
			e.udpConn.Close()
		}
		var err error
		err = kernel.WithNS(e.ns, func() error {
			e.udpConn, err = net.DialTimeout("udp4", e.udpAddr, 500*time.Millisecond)
			if err != nil {
				return err
			}

			return e.populateUDPExpectedValues(expected)
		})
		if err != nil {
			return err
		}

		_, err = e.udpConn.Write([]byte("foo"))
		return err
	}

	return fmt.Errorf("invalid guess %v", status)
}

func (e *conntrackEventGenerator) populateUDPExpectedValues(expected *ConntrackValues) error {
	saddr, daddr, _, _, err := extractIPsAndPorts(e.udpConn)
	if err != nil {
		return err
	}

	expected.Saddr = saddr
	expected.Daddr = daddr
	// IPS_CONFIRMED | IPS_SRC_NAT_DONE | IPS_DST_NAT_DONE
	// see https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/netfilter/nf_conntrack_common.h#L42
	expected.Status = 0x188
	expected.Netns, err = kernel.GetCurrentIno()
	if err != nil {
		return err
	}

	return nil
}

// Close conntrack event generator
func (e *conntrackEventGenerator) Close() {
	if e.udpDone != nil {
		e.udpDone()
	}
	if e.udpConn != nil {
		e.udpConn.Close()
	}
}
