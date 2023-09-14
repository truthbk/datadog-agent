// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var errOffsetOverflow = errors.New("offset exceeded threshold")

type tracerOffsetGuesser struct {
	m          *manager.Manager
	status     *TracerStatus
	guesser    *offsetGuesser[TracerValues, TracerOffsets]
	guessTCPv6 bool
	guessUDPv6 bool
	iterations uint
}

func NewTracerOffsetGuesser() (OffsetGuesser, error) {
	return &tracerOffsetGuesser{
		m: &manager.Manager{
			Maps: []*manager.Map{
				{Name: "connectsock_ipv6"},
				{Name: probes.TracerStatusMap},
			},
			PerfMaps: []*manager.PerfMap{},
			Probes: []*manager.Probe{
				{ProbeIdentificationPair: idPair(probes.TCPGetSockOpt)},
				{ProbeIdentificationPair: idPair(probes.SockGetSockOpt)},
				{ProbeIdentificationPair: idPair(probes.TCPv6Connect)},
				{ProbeIdentificationPair: idPair(probes.IPMakeSkb)},
				{ProbeIdentificationPair: idPair(probes.IP6MakeSkb)},
				{ProbeIdentificationPair: idPair(probes.IP6MakeSkbPre470)},
				{ProbeIdentificationPair: idPair(probes.TCPv6ConnectReturn), KProbeMaxActive: 128},
				{ProbeIdentificationPair: idPair(probes.NetDevQueue)},
			},
		},
	}, nil
}

func (t *tracerOffsetGuesser) Manager() *manager.Manager {
	return t.m
}

func (t *tracerOffsetGuesser) Close() {
	ebpfcheck.RemoveNameMappings(t.m)
	if err := t.m.Stop(manager.CleanAll); err != nil {
		log.Warnf("error stopping tracer offset guesser: %s", err)
	}
}

func expectedValues(conn net.Conn) (*TracerValues, error) {
	netns, err := kernel.GetCurrentIno()
	if err != nil {
		return nil, err
	}

	tcpInfo, err := TCPGetInfo(conn)
	if err != nil {
		return nil, err
	}

	saddr, daddr, sport, dport, err := extractIPsAndPorts(conn)
	if err != nil {
		return nil, err
	}

	return &TracerValues{
		Saddr:        saddr,
		Daddr:        daddr,
		Sport:        sport,
		Sport_via_sk: sport,
		Dport:        dport,
		Dport_via_sk: dport,
		Netns:        netns,
		Family:       syscall.AF_INET,
		Rtt:          tcpInfo.Rtt,
		Rtt_var:      tcpInfo.Rttvar,
	}, nil
}

func waitUntilStable(conn net.Conn, window time.Duration, attempts int) (*TracerValues, error) {
	var (
		current *TracerValues
		prev    *TracerValues
		err     error
	)
	for i := 0; i <= attempts; i++ {
		current, err = expectedValues(conn)
		if err != nil {
			return nil, err
		}

		if prev != nil && *prev == *current {
			return current, nil
		}

		prev = current
		time.Sleep(window)
	}

	return nil, errors.New("unstable TCP socket params")
}

func (*tracerOffsetGuesser) Probes(c *config.Config) (map[probes.ProbeFuncName]struct{}, error) {
	p := map[probes.ProbeFuncName]struct{}{}
	enableProbe(p, probes.TCPGetSockOpt)
	enableProbe(p, probes.SockGetSockOpt)
	enableProbe(p, probes.IPMakeSkb)
	kv, err := kernel.HostVersion()
	if err != nil {
		return nil, fmt.Errorf("could not kernel version: %w", err)
	}
	if kv >= kernel.VersionCode(4, 7, 0) {
		enableProbe(p, probes.NetDevQueue)
	}

	if c.CollectTCPv6Conns || c.CollectUDPv6Conns {
		enableProbe(p, probes.TCPv6Connect)
		enableProbe(p, probes.TCPv6ConnectReturn)
	}

	if c.CollectUDPv6Conns {
		if kv < kernel.VersionCode(5, 18, 0) {
			if kv < kernel.VersionCode(4, 7, 0) {
				enableProbe(p, probes.IP6MakeSkbPre470)
			} else {
				enableProbe(p, probes.IP6MakeSkb)
			}
		}
	}
	return p, nil
}

// checkAndUpdateCurrentOffset checks the value for the current offset stored
// in the eBPF map against the expected value, incrementing the offset if it
// doesn't match, or going to the next field to guess if it does
func (t *tracerOffsetGuesser) checkAndUpdateCurrentOffset(mp *ebpf.Map, expected *TracerValues, maxRetries *int) error {
	// get the updated map value, so we can check if the current offset is
	// the right one
	if err := mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error reading tracer_status: %v", err)
	}

	if err := t.guesser.iterate(expected, maxRetries); err != nil {
		return err
	}

	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error updating tracer_t.status: %v", err)
	}

	return nil
}

// Guess expects manager.Manager to contain a map named tracer_status and helps initialize the
// tracer by guessing the right struct sock kernel struct offsets. Results are
// returned as constants which are runtime-edited into the tracer eBPF code.
//
// To guess the offsets, we create connections from localhost (127.0.0.1) to
// 127.0.0.2:$PORT, where we have a server listening. We store the current
// possible offset and expected value of each field in a eBPF map. In kernel-space
// we rely on two different kprobes: `tcp_getsockopt` and `tcp_connect_v6`. When they're
// are triggered, we store the value of
//
//	(struct sock *)skp + possible_offset
//
// in the eBPF map. Then, back in userspace (checkAndUpdateCurrentOffset()), we
// check that value against the expected value of the field, advancing the
// offset and repeating the process until we find the value we expect. Then, we
// guess the next field.
func (t *tracerOffsetGuesser) Guess(cfg *config.Config) ([]manager.ConstantEditor, error) {
	mp, _, err := t.m.GetMap(probes.TracerStatusMap)
	if err != nil {
		return nil, fmt.Errorf("unable to find map %s: %s", probes.TracerStatusMap, err)
	}

	// if we already have the offsets, just return
	err = mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(t.status))
	if err == nil && State(t.status.State.State) == StateReady {
		return t.getConstantEditors(), nil
	}

	kv, err := kernel.HostVersion()
	if err != nil {
		return nil, fmt.Errorf("error getting kernel version: %w", err)
	}
	kv470 := kernel.VersionCode(4, 7, 0)

	// When reading kernel structs at different offsets, don't go over the set threshold
	// Defaults to 400, with a max of 3000. This is an arbitrary choice to avoid infinite loops.
	threshold := cfg.OffsetGuessThreshold

	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	t.guessUDPv6 = cfg.CollectUDPv6Conns
	t.guessTCPv6 = cfg.CollectTCPv6Conns
	t.status = &TracerStatus{
		State: GuessState{
			State: uint64(StateChecking),
			What:  uint64(GuessSAddr),
		},
	}
	processName := filepath.Base(os.Args[0])
	if len(processName) > ProcCommMaxLen { // Truncate process name if needed
		processName = processName[:ProcCommMaxLen]
	}
	copy(t.status.State.Proc.Comm[:], processName)
	t.guesser = newOffsetGuesser(&t.status.State, &t.status.Values, &t.status.Offsets)

	valuesType := reflect.TypeOf((*TracerValues)(nil)).Elem()
	valueStructField := func(name string) reflect.StructField {
		f, ok := valuesType.FieldByName(name)
		if !ok {
			panic("unable to find struct field " + name)
		}
		return f
	}

	// fields are guessed in the order of this slice
	t.guesser.fields = []guessField[TracerValues, TracerOffsets]{
		{
			what:        GuessSAddr,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Saddr")},
			offsetField: &t.status.Offsets.Saddr,
		},
		{
			what:        GuessDAddr,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Daddr")},
			offsetField: &t.status.Offsets.Daddr,
		},
		{
			what:        GuessDPort,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Dport")},
			offsetField: &t.status.Offsets.Dport,
		},
		{
			what:        GuessFamily,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Family")},
			offsetField: &t.status.Offsets.Family,
			// we know the family ((struct __sk_common)->skc_family) is
			// after the skc_dport field, so we start from there
			startOffset: &t.status.Offsets.Dport,
		},
		{
			what:        GuessSPort,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Sport")},
			offsetField: &t.status.Offsets.Sport,
			// we know the sport ((struct inet_sock)->inet_sport) is
			// after the family field, so we start from there
			startOffset: &t.status.Offsets.Family,
			threshold:   thresholdInetSock,
		},
		{
			what:        GuessSAddrFl4,
			subject:     structFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Saddr_fl4")},
			offsetField: &t.status.Offsets.Saddr_fl4,
			nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
				if !equal {
					return advanceField[TracerValues, TracerOffsets](4)(field, allFields, equal)
				}
				return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
			},
		},
		{
			what:        GuessDAddrFl4,
			subject:     structFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Daddr_fl4")},
			offsetField: &t.status.Offsets.Daddr_fl4,
			nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
				if !equal {
					return advanceField[TracerValues, TracerOffsets](3)(field, allFields, equal)
				}
				return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
			},
		},
		{
			what:        GuessSPortFl4,
			subject:     structFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Sport_fl4")},
			offsetField: &t.status.Offsets.Sport_fl4,
			nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
				if !equal {
					return advanceField[TracerValues, TracerOffsets](2)(field, allFields, equal)
				}
				return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
			},
		},
		{
			what:        GuessDPortFl4,
			subject:     structFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Dport_fl4")},
			offsetField: &t.status.Offsets.Dport_fl4,
		},
	}

	if t.guessUDPv6 {
		t.guesser.fields = append(t.guesser.fields,
			guessField[TracerValues, TracerOffsets]{
				what:        GuessSAddrFl6,
				subject:     structFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Saddr_fl6")},
				offsetField: &t.status.Offsets.Saddr_fl6,
				nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
					if !equal {
						return advanceField[TracerValues, TracerOffsets](4)(field, allFields, equal)
					}
					return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
				},
			},
			guessField[TracerValues, TracerOffsets]{
				what:        GuessDAddrFl6,
				subject:     structFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Daddr_fl6")},
				offsetField: &t.status.Offsets.Daddr_fl6,
				nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
					if !equal {
						return advanceField[TracerValues, TracerOffsets](3)(field, allFields, equal)
					}
					return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
				},
			},
			guessField[TracerValues, TracerOffsets]{
				what:        GuessSPortFl6,
				subject:     structFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Sport_fl6")},
				offsetField: &t.status.Offsets.Sport_fl6,
				nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
					if !equal {
						return advanceField[TracerValues, TracerOffsets](2)(field, allFields, equal)
					}
					return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
				},
			},
			guessField[TracerValues, TracerOffsets]{
				what:        GuessDPortFl6,
				subject:     structFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Dport_fl6")},
				offsetField: &t.status.Offsets.Dport_fl6,
			},
		)
	}

	t.guesser.fields = append(t.guesser.fields,
		guessField[TracerValues, TracerOffsets]{
			what:        GuessNetNS,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Netns")},
			offsetField: &t.status.Offsets.Netns,
			incrementFunc: func(field *guessField[TracerValues, TracerOffsets], offsets *TracerOffsets, errored bool) {
				offsets.Ino++
				if errored || offsets.Ino >= field.threshold {
					offsets.Ino = 0
					offsets.Netns++
				}
			},
			nextFunc: func(field *guessField[TracerValues, TracerOffsets], allFields *guessFields[TracerValues, TracerOffsets], equal bool) GuessWhat {
				log.Debugf("Successfully guessed %s with offset of %d bytes", "ino", t.status.Offsets.Ino)
				return advanceField[TracerValues, TracerOffsets](1)(field, allFields, equal)
			},
		},
		guessField[TracerValues, TracerOffsets]{
			what:        GuessRTT,
			subject:     structSock,
			valueFields: []reflect.StructField{valueStructField("Rtt"), valueStructField("Rtt_var")},
			offsetField: &t.status.Offsets.Rtt,
			threshold:   thresholdInetSock,
		},
		guessField[TracerValues, TracerOffsets]{
			what:        GuessSocketSK,
			subject:     structSocket,
			valueFields: []reflect.StructField{valueStructField("Sport_via_sk"), valueStructField("Dport_via_sk")},
			valueSize:   SizeofStructSock,
			offsetField: &t.status.Offsets.Socket_sk,
		},
	)

	// if we are on kernel version < 4.7, net_dev_queue tracepoint will not be activated, and thus we should skip
	// the guessing for `struct sk_buff`
	if kv >= kv470 {
		t.guesser.fields = append(t.guesser.fields,
			guessField[TracerValues, TracerOffsets]{
				what:        GuessSKBuffSock,
				subject:     structSKBuff,
				valueFields: []reflect.StructField{valueStructField("Sport_via_sk_via_sk_buff"), valueStructField("Dport_via_sk_via_sk_buff")},
				valueSize:   SizeofSKBuffSock,
				offsetField: &t.status.Offsets.Sk_buff_sock,
			},
			guessField[TracerValues, TracerOffsets]{
				what:        GuessSKBuffTransportHeader,
				subject:     structSKBuff,
				valueSize:   SizeofSKBuffTransportHeader,
				offsetField: &t.status.Offsets.Sk_buff_transport_header,
				equalFunc: func(field *guessField[TracerValues, TracerOffsets], val *TracerValues, _ *TracerValues) bool {
					networkDiffFromMac := val.Network_header - val.Mac_header
					transportDiffFromNetwork := val.Transport_header - val.Network_header
					// TODO document where these values come from!
					return networkDiffFromMac == 14 && transportDiffFromNetwork == 20
				},
			},
			guessField[TracerValues, TracerOffsets]{
				what:        GuessSKBuffHead,
				subject:     structSKBuff,
				valueFields: []reflect.StructField{valueStructField("Sport_via_sk_buff"), valueStructField("Dport_via_sk_buff")},
				valueSize:   SizeofSKBuffHead,
				offsetField: &t.status.Offsets.Sk_buff_head,
			},
		)
	}

	if t.guessUDPv6 || t.guessTCPv6 {
		t.guesser.fields = append(t.guesser.fields,
			guessField[TracerValues, TracerOffsets]{
				what:        GuessDAddrIPv6,
				subject:     structSock,
				valueFields: []reflect.StructField{valueStructField("Daddr_ipv6")},
				offsetField: &t.status.Offsets.Daddr_ipv6,
			},
		)
	}

	if err := t.guesser.fields.fixup(threshold); err != nil {
		return nil, err
	}

	eventGenerator, err := newTracerEventGenerator(t.guessUDPv6)
	if err != nil {
		return nil, err
	}
	defer eventGenerator.Close()

	// initialize map
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return nil, fmt.Errorf("error initializing tracer_status map: %v", err)
	}

	// If the kretprobe for tcp_v4_connect() is configured with a too-low maxactive, some kretprobe might be missing.
	// In this case, we detect it and try again. See: https://github.com/weaveworks/tcptracer-bpf/issues/24
	maxRetries := 100

	// Retrieve expected values from local connection
	expected, err := waitUntilStable(eventGenerator.conn, 200*time.Millisecond, 5)
	if err != nil {
		return nil, fmt.Errorf("error retrieving expected value: %w", err)
	}

	err = eventGenerator.populateUDPExpectedValues(expected)
	if err != nil {
		return nil, fmt.Errorf("error retrieving expected value: %w", err)
	}
	log.Tracef("expected values: %+v", expected)

	log.Debugf("Checking for offsets with threshold of %d", threshold)
	for State(t.status.State.State) != StateReady {
		if err := eventGenerator.Generate(GuessWhat(t.status.State.What), expected); err != nil {
			return nil, err
		}

		if err := t.checkAndUpdateCurrentOffset(mp, expected, &maxRetries); err != nil {
			return nil, err
		}
	}
	log.Debugf("finished in %d iterations", t.iterations)

	return t.getConstantEditors(), nil
}

func (t *tracerOffsetGuesser) getConstantEditors() []manager.ConstantEditor {
	fl4offsets := t.guesser.fields.whatField(GuessSAddrFl4).finished &&
		t.guesser.fields.whatField(GuessDAddrFl4).finished &&
		t.guesser.fields.whatField(GuessSPortFl4).finished &&
		t.guesser.fields.whatField(GuessDPortFl4).finished
	fl6offsets := t.guesser.fields.whatField(GuessSAddrFl6).finished &&
		t.guesser.fields.whatField(GuessDAddrFl6).finished &&
		t.guesser.fields.whatField(GuessSPortFl6).finished &&
		t.guesser.fields.whatField(GuessDPortFl6).finished

	return []manager.ConstantEditor{
		{Name: "offset_saddr", Value: t.status.Offsets.Saddr},
		{Name: "offset_daddr", Value: t.status.Offsets.Daddr},
		{Name: "offset_sport", Value: t.status.Offsets.Sport},
		{Name: "offset_dport", Value: t.status.Offsets.Dport},
		{Name: "offset_netns", Value: t.status.Offsets.Netns},
		{Name: "offset_ino", Value: t.status.Offsets.Ino},
		{Name: "offset_family", Value: t.status.Offsets.Family},
		{Name: "offset_rtt", Value: t.status.Offsets.Rtt},
		{Name: "offset_rtt_var", Value: t.status.Offsets.Rtt_var},
		{Name: "offset_daddr_ipv6", Value: t.status.Offsets.Daddr_ipv6},
		{Name: "offset_saddr_fl4", Value: t.status.Offsets.Saddr_fl4},
		{Name: "offset_daddr_fl4", Value: t.status.Offsets.Daddr_fl4},
		{Name: "offset_sport_fl4", Value: t.status.Offsets.Sport_fl4},
		{Name: "offset_dport_fl4", Value: t.status.Offsets.Dport_fl4},
		boolConst("fl4_offsets", fl4offsets),
		{Name: "offset_saddr_fl6", Value: t.status.Offsets.Saddr_fl6},
		{Name: "offset_daddr_fl6", Value: t.status.Offsets.Daddr_fl6},
		{Name: "offset_sport_fl6", Value: t.status.Offsets.Sport_fl6},
		{Name: "offset_dport_fl6", Value: t.status.Offsets.Dport_fl6},
		boolConst("fl6_offsets", fl6offsets),
		{Name: "offset_socket_sk", Value: t.status.Offsets.Socket_sk},
		{Name: "offset_sk_buff_sock", Value: t.status.Offsets.Sk_buff_sock},
		{Name: "offset_sk_buff_transport_header", Value: t.status.Offsets.Sk_buff_transport_header},
		{Name: "offset_sk_buff_head", Value: t.status.Offsets.Sk_buff_head},
	}
}
