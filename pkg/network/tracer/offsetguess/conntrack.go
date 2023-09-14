// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

var _ guesser[ConntrackValues, ConntrackOffsets] = (*conntrackOffsetGuesser)(nil)

type conntrackOffsetGuesser struct {
	m            *manager.Manager
	guess        *ConntrackGuess
	fields       guessFields[ConntrackValues, ConntrackOffsets]
	tcpv6Enabled uint64
	udpv6Enabled uint64
}

func (c *conntrackOffsetGuesser) Status() *GuessStatus {
	return &c.guess.Status
}

func (c *conntrackOffsetGuesser) Fields() *guessFields[ConntrackValues, ConntrackOffsets] {
	return &c.fields
}

func (c *conntrackOffsetGuesser) Values() *ConntrackValues {
	return &c.guess.Values
}

func (c *conntrackOffsetGuesser) Offsets() *ConntrackOffsets {
	return &c.guess.Offsets
}

func NewConntrackOffsetGuesser(cfg *config.Config) (OffsetGuesser, error) {
	consts, err := Tracer.Offsets(cfg)
	if err != nil {
		return nil, err
	}

	// TODO this is a strange way to pass constants between offset guessers
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
		return nil, fmt.Errorf("ino offset must not be 0")
	}

	return &conntrackOffsetGuesser{
		m: &manager.Manager{
			Maps: []*manager.Map{
				{Name: probes.ConntrackGuessMap},
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
		guess:        &ConntrackGuess{Offsets: ConntrackOffsets{Ino: offsetIno}},
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

func (c *conntrackOffsetGuesser) Probes(_ *config.Config) (map[probes.ProbeFuncName]struct{}, error) {
	p := map[probes.ProbeFuncName]struct{}{}
	enableProbe(p, probes.ConntrackHashInsert)
	return p, nil
}

func (c *conntrackOffsetGuesser) getConstantEditors() []manager.ConstantEditor {
	return []manager.ConstantEditor{
		{Name: "offset_ct_origin", Value: c.guess.Offsets.Origin},
		{Name: "offset_ct_reply", Value: c.guess.Offsets.Reply},
		{Name: "offset_ct_status", Value: c.guess.Offsets.Status},
		{Name: "offset_ct_netns", Value: c.guess.Offsets.Netns},
		{Name: "offset_ct_ino", Value: c.guess.Offsets.Ino},
		{Name: "tcpv6_enabled", Value: c.tcpv6Enabled},
		{Name: "udpv6_enabled", Value: c.udpv6Enabled},
	}
}

// checkAndUpdateCurrentOffset checks the value for the current offset stored
// in the eBPF map against the expected value, incrementing the offset if it
// doesn't match, or going to the next field to guess if it does
func (c *conntrackOffsetGuesser) checkAndUpdateCurrentOffset(mp *ebpf.Map, expected *ConntrackValues, maxRetries *int) error {
	// get the updated map value, so we can check if the current offset is
	// the right one
	if err := mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(c.guess)); err != nil {
		return fmt.Errorf("error reading %s: %v", probes.ConntrackGuessMap, err)
	}

	if err := iterate[ConntrackValues, ConntrackOffsets](c, expected, maxRetries); err != nil {
		return err
	}

	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(c.guess)); err != nil {
		return fmt.Errorf("error updating %s: %v", probes.ConntrackGuessMap, err)
	}

	return nil
}

func (c *conntrackOffsetGuesser) Guess(cfg *config.Config) ([]manager.ConstantEditor, error) {
	mp, _, err := c.m.GetMap(probes.ConntrackGuessMap)
	if err != nil {
		return nil, fmt.Errorf("unable to find map %s: %s", probes.ConntrackGuessMap, err)
	}

	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c.guess.Status.SetProcessName(filepath.Base(os.Args[0]))

	// if we already have the offsets, just return
	err = mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(c.guess))
	if err == nil && GuessState(c.guess.Status.State) == StateReady {
		return c.getConstantEditors(), nil
	}

	valueStructField := valueFieldFunc[ConntrackValues, ConntrackOffsets](c)
	c.fields = []guessField[ConntrackValues, ConntrackOffsets]{
		{
			what:        GuessCtTupleOrigin,
			subject:     structNFConn,
			valueSize:   sizeofNfConntrackTuple,
			valueFields: []reflect.StructField{valueStructField("Saddr")},
			offsetField: &c.guess.Offsets.Origin,
		},
		{
			what:        GuessCtTupleReply,
			subject:     structNFConn,
			valueSize:   sizeofNfConntrackTuple,
			valueFields: []reflect.StructField{valueStructField("Daddr")},
			offsetField: &c.guess.Offsets.Reply,
			startOffset: &c.guess.Offsets.Origin,
		},
		{
			what:        GuessCtStatus,
			subject:     structNFConn,
			valueFields: []reflect.StructField{valueStructField("Status")},
			offsetField: &c.guess.Offsets.Status,
		},
		{
			what:        GuessCtNet,
			subject:     structNFConn,
			valueFields: []reflect.StructField{valueStructField("Netns")},
			offsetField: &c.guess.Offsets.Netns,
			startOffset: &c.guess.Offsets.Status,
		},
	}

	if err := c.fields.validate(cfg.OffsetGuessThreshold); err != nil {
		return nil, err
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

	c.fields.reset()
	c.guess.Status.State = uint32(StateChecking)
	c.guess.Status.What = uint32(GuessCtTupleOrigin)

	// initialize map
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(c.guess)); err != nil {
		return nil, fmt.Errorf("error initializing %s map: %v", probes.ConntrackGuessMap, err)
	}

	log.Debugf("offset guessing with default threshold of %d", cfg.OffsetGuessThreshold)
	maxRetries := 100
	expected := &ConntrackValues{}
	for GuessState(c.guess.Status.State) != StateReady {
		if err := eventGenerator.Generate(GuessWhat(c.guess.Status.What), expected); err != nil {
			return nil, err
		}

		if err := c.checkAndUpdateCurrentOffset(mp, expected, &maxRetries); err != nil {
			return nil, err
		}
	}

	return c.getConstantEditors(), nil
}
