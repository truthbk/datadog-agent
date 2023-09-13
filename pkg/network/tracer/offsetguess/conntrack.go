// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netns"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// sizeof(struct nf_conntrack_tuple), see https://github.com/torvalds/linux/blob/master/include/net/netfilter/nf_conntrack_tuple.h
const sizeofNfConntrackTuple = 40

type conntrackOffsetGuesser struct {
	m            *manager.Manager
	status       *ConntrackStatus
	tcpv6Enabled uint64
	udpv6Enabled uint64
}

func NewConntrackOffsetGuesser(cfg *config.Config) (OffsetGuesser, error) {
	consts, err := Tracer.Offsets(cfg)
	if err != nil {
		return nil, err
	}

	var offsetIno uint64
	var tcpv6Enabled, udpv6Enabled uint64
	for _, c := range consts {
		switch c.Name {
		case "offset_ino":
			offsetIno = c.Value.(uint64)
		case "tcpv6_enabled":
			tcpv6Enabled = c.Value.(uint64)
		case "udpv6_enabled":
			udpv6Enabled = c.Value.(uint64)
		}
	}

	if offsetIno == 0 {
		return nil, fmt.Errorf("ino offset is 0")
	}

	return &conntrackOffsetGuesser{
		m: &manager.Manager{
			Maps: []*manager.Map{
				{Name: probes.ConntrackStatusMap},
			},
			PerfMaps: []*manager.PerfMap{},
			Probes: []*manager.Probe{
				{ProbeIdentificationPair: idPair(probes.ConntrackHashInsert)},
				// have to add this for older kernels since loading
				// it twice in a process (once by the tracer offset guesser)
				// does not seem to work; this will be not be enabled,
				// so explicitly disabled, and the manager won't load it
				{ProbeIdentificationPair: idPair(probes.NetDevQueue)}},
		},
		status:       &ConntrackStatus{Offsets: ConntrackOffsets{Ino: offsetIno}},
		tcpv6Enabled: tcpv6Enabled,
		udpv6Enabled: udpv6Enabled,
	}, nil
}

func (c *conntrackOffsetGuesser) Manager() *manager.Manager {
	return c.m
}

func (c *conntrackOffsetGuesser) Close() {
	ebpfcheck.RemoveNameMappings(c.m)
	if err := c.m.Stop(manager.CleanAll); err != nil {
		log.Warnf("error stopping conntrack offset guesser: %s", err)
	}
}

func (c *conntrackOffsetGuesser) Probes(cfg *config.Config) (map[probes.ProbeFuncName]struct{}, error) {
	p := map[probes.ProbeFuncName]struct{}{}
	enableProbe(p, probes.ConntrackHashInsert)
	return p, nil
}

func (c *conntrackOffsetGuesser) getConstantEditors() []manager.ConstantEditor {
	return []manager.ConstantEditor{
		{Name: "offset_ct_origin", Value: c.status.Offsets.Origin},
		{Name: "offset_ct_reply", Value: c.status.Offsets.Reply},
		{Name: "offset_ct_status", Value: c.status.Offsets.Status},
		{Name: "offset_ct_netns", Value: c.status.Offsets.Netns},
		{Name: "offset_ct_ino", Value: c.status.Offsets.Ino},
		{Name: "tcpv6_enabled", Value: c.tcpv6Enabled},
		{Name: "udpv6_enabled", Value: c.udpv6Enabled},
	}
}

// checkAndUpdateCurrentOffset checks the value for the current offset stored
// in the eBPF map against the expected value, incrementing the offset if it
// doesn't match, or going to the next field to guess if it does
func (c *conntrackOffsetGuesser) checkAndUpdateCurrentOffset(mp *ebpf.Map, expected *ConntrackValues, maxRetries *int, threshold uint64) error {
	// get the updated map value so we can check if the current offset is
	// the right one
	if err := mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(c.status)); err != nil {
		return fmt.Errorf("error reading conntrack_status: %v", err)
	}

	if State(c.status.State) != StateChecked {
		if *maxRetries == 0 {
			return fmt.Errorf("invalid guessing state while guessing %s, got %s expected %s",
				GuessWhat(c.status.What), State(c.status.State), StateChecked)
		}
		*maxRetries--
		time.Sleep(10 * time.Millisecond)
		return nil
	}
	switch GuessWhat(c.status.What) {
	case GuessCtTupleOrigin:
		if c.status.Values.Saddr == expected.Saddr {
			// the reply tuple comes always after the origin tuple
			c.status.Offsets.Reply = c.status.Offsets.Origin + sizeofNfConntrackTuple
			c.logAndAdvance(c.status.Offsets.Origin, GuessCtTupleReply)
			break
		}
		c.status.Offsets.Origin++
	case GuessCtTupleReply:
		if c.status.Values.Daddr == expected.Daddr {
			c.logAndAdvance(c.status.Offsets.Reply, GuessCtStatus)
			break
		}
		c.status.Offsets.Reply++
	case GuessCtStatus:
		if c.status.Values.Status == expected.Status {
			c.status.Offsets.Netns = c.status.Offsets.Status + 1
			c.logAndAdvance(c.status.Offsets.Status, GuessCtNet)
			break
		}
		c.status.Offsets.Status++
	case GuessCtNet:
		if c.status.Values.Netns == expected.Netns {
			c.logAndAdvance(c.status.Offsets.Netns, GuessNotApplicable)
			return c.setReadyState(mp)
		}
		c.status.Offsets.Netns++
	default:
		return fmt.Errorf("unexpected field to guess: %s", GuessWhat(c.status.What))
	}

	c.status.State = uint64(StateChecking)
	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(c.status)); err != nil {
		return fmt.Errorf("error updating tracer_t.status: %v", err)
	}

	return nil

}

func (c *conntrackOffsetGuesser) setReadyState(mp *ebpf.Map) error {
	c.status.State = uint64(StateReady)
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(c.status)); err != nil {
		return fmt.Errorf("error updating tracer_status: %v", err)
	}
	return nil
}

func (c *conntrackOffsetGuesser) logAndAdvance(offset uint64, next GuessWhat) {
	guess := GuessWhat(c.status.What)
	if offset != notApplicable {
		log.Debugf("Successfully guessed %s with offset of %d bytes", guess, offset)
	} else {
		log.Debugf("Could not guess offset for %s", guess)
	}
	if next != GuessNotApplicable {
		log.Debugf("Started offset guessing for %s", next)
		c.status.What = uint64(next)
	}
}

func (c *conntrackOffsetGuesser) Guess(cfg *config.Config) ([]manager.ConstantEditor, error) {
	mp, _, err := c.m.GetMap(probes.ConntrackStatusMap)
	if err != nil {
		return nil, fmt.Errorf("unable to find map %s: %s", probes.ConntrackStatusMap, err)
	}

	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	processName := filepath.Base(os.Args[0])
	if len(processName) > ProcCommMaxLen { // Truncate process name if needed
		processName = processName[:ProcCommMaxLen]
	}
	copy(c.status.Proc.Comm[:], processName)

	// if we already have the offsets, just return
	err = mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(c.status))
	if err == nil && State(c.status.State) == StateReady {
		return c.getConstantEditors(), nil
	}

	// we may have to run the offset guessing twice, once
	// in the current network namespace and another in the
	// root network namespace if we are not running in the
	// root network namespace already. This is necessary
	// since conntrack may not be active in the current
	// namespace, and so the offset guessing will fail since
	// no conntrack events will be generated in eBPF
	var nss []netns.NsHandle
	currentNs, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer currentNs.Close()
	nss = append(nss, currentNs)

	rootNs, err := kernel.GetRootNetNamespace(kernel.ProcFSRoot())
	if err != nil {
		return nil, err
	}
	defer rootNs.Close()
	if !currentNs.Equal(rootNs) {
		nss = append(nss, rootNs)
	}

	for _, ns := range nss {
		var consts []manager.ConstantEditor
		if consts, err = c.runOffsetGuessing(cfg, ns, mp); err == nil {
			return consts, nil
		}
	}

	return nil, err
}

func (c *conntrackOffsetGuesser) runOffsetGuessing(cfg *config.Config, ns netns.NsHandle, mp *ebpf.Map) ([]manager.ConstantEditor, error) {
	log.Debugf("running conntrack offset guessing with ns %s", ns)
	eventGenerator, err := newConntrackEventGenerator(ns)
	if err != nil {
		return nil, err
	}
	defer eventGenerator.Close()

	c.status.State = uint64(StateChecking)
	c.status.What = uint64(GuessCtTupleOrigin)

	// initialize map
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(c.status)); err != nil {
		return nil, fmt.Errorf("error initializing conntrack_c.status map: %v", err)
	}

	// When reading kernel structs at different offsets, don't go over the set threshold
	// Defaults to 400, with a max of 3000. This is an arbitrary choice to avoid infinite loops.
	threshold := cfg.OffsetGuessThreshold

	maxRetries := 100

	log.Debugf("Checking for offsets with threshold of %d", threshold)
	expected := &ConntrackValues{}
	for State(c.status.State) != StateReady {
		if err := eventGenerator.Generate(GuessWhat(c.status.What), expected); err != nil {
			return nil, err
		}

		if err := c.checkAndUpdateCurrentOffset(mp, expected, &maxRetries, threshold); err != nil {
			return nil, err
		}

		// Stop at a reasonable offset so we don't run forever.
		// Reading too far away in kernel memory is not a big deal:
		// probe_kernel_read() handles faults gracefully.
		if c.status.Offsets.Netns >= threshold || c.status.Offsets.Status >= threshold ||
			c.status.Offsets.Origin >= threshold || c.status.Offsets.Reply >= threshold {
			return nil, fmt.Errorf("overflow while guessing %s, bailing out", GuessWhat(c.status.What))
		}
	}

	return c.getConstantEditors(), nil

}

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

	return fmt.Errorf("invalid status %v", status)
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

func (e *conntrackEventGenerator) Close() {
	if e.udpDone != nil {
		e.udpDone()
	}
	if e.udpConn != nil {
		e.udpConn.Close()
	}
}
