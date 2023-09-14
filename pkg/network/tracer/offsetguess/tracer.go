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

	"github.com/cilium/ebpf"
	"golang.org/x/exp/slices"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	tcpGetSockOptKProbeNotCalled uint64 = 0
	tcpGetSockOptKProbeCalled    uint64 = 1
)

var tcpKprobeCalledString = map[uint64]string{
	tcpGetSockOptKProbeNotCalled: "tcp_getsockopt kprobe not executed",
	tcpGetSockOptKProbeCalled:    "tcp_getsockopt kprobe executed",
}

var errOffsetOverflow = errors.New("offset exceeded threshold")

type tracerOffsetGuesser struct {
	m           *manager.Manager
	status      *TracerStatus
	guessFields guessFields
	guessTCPv6  bool
	guessUDPv6  bool
	iterations  uint
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

	tcpInfo, err := TcpGetInfo(conn)
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

func dfaultEqualFunc(field *guessField, val *TracerValues, exp *TracerValues) bool {
	for _, vf := range field.valueFields {
		valueField := reflect.Indirect(reflect.ValueOf(val)).FieldByIndex(vf.Index)
		expectedField := reflect.Indirect(reflect.ValueOf(exp)).FieldByIndex(vf.Index)
		if !valueField.Equal(expectedField) {
			return false
		}
	}
	return true
}

func dfaultIncrementFunc(field *guessField, _ *TracerOffsets, _ bool) {
	*field.offsetField++
}

func advanceField(n int) func(field *guessField, allFields *guessFields, _ bool) GuessWhat {
	return func(field *guessField, allFields *guessFields, _ bool) GuessWhat {
		fieldIndex := slices.IndexFunc(*allFields, func(f guessField) bool {
			return f.what == field.what
		})
		fieldIndex += n
		if fieldIndex >= len(*allFields) {
			return GuessNotApplicable
		}
		return (*allFields)[fieldIndex].what
	}
}

var dfaultNextFunc = advanceField(1)

type GuessSubject int

const (
	StructSock GuessSubject = iota
	StructSocket
	StructFlowI4
	StructFlowI6
	StructSKBuff
)

type guessField struct {
	what          GuessWhat
	subject       GuessSubject
	finished      bool
	optional      bool
	valueFields   []reflect.StructField
	valueSize     uint64
	offsetField   *uint64
	startOffset   *uint64
	threshold     uint64
	equalFunc     func(field *guessField, val *TracerValues, exp *TracerValues) bool
	incrementFunc func(field *guessField, offsets *TracerOffsets, errored bool)
	nextFunc      func(field *guessField, allFields *guessFields, equal bool) GuessWhat
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

	if State(t.status.State) != StateChecked {
		if *maxRetries == 0 {
			return fmt.Errorf("invalid guessing state while guessing %s, got %s expected %s. %v",
				GuessWhat(t.status.What), State(t.status.State), StateChecked, tcpKprobeCalledString[t.status.Info_kprobe_status])
		}
		*maxRetries--
		time.Sleep(10 * time.Millisecond)
		return nil
	}
	t.iterations++
	//log.Warnf("what: %s\noffsets: %+v\nval: %+v\nexp: %+v", GuessWhat(t.status.What), t.status.Offsets, &t.status.Values, expected)
	//log.Warnf("post: %+v", t.status.Offsets)

	field := t.guessFields.whatField(GuessWhat(t.status.What))
	if field == nil {
		return fmt.Errorf("invalid offset guessing field %d", t.status.What)
	}

	// check if used offset overlaps. If so, ignore equality because it isn't a valid offset
	// we check after usage, because the eBPF code can adjust the offset due to alignment rules
	overlapped := field.jumpPastOverlaps(t.guessFields.subjectFields(field.subject))
	if overlapped {
		// skip to checking the newly set offset
		t.status.State = uint64(StateChecking)
		goto NextCheck
	}

	if field.equalFunc(field, &t.status.Values, expected) {
		offset := *field.offsetField
		field.finished = true
		next := field.nextFunc(field, &t.guessFields, true)
		if err := t.logAndAdvance(offset, next); err != nil {
			return err
		}
		goto NextCheck
	}

	field.incrementFunc(field, &t.status.Offsets, t.status.Err != 0)
	t.status.State = uint64(StateChecking)

NextCheck:
	if *field.offsetField >= field.threshold {
		if field.optional {
			next := field.nextFunc(field, &t.guessFields, false)
			if err := t.logAndAdvance(notApplicable, next); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%s overflow: %w", GuessWhat(t.status.What), errOffsetOverflow)
		}
	}

	log.Warnf("pre : %+v", t.status.Offsets)
	t.status.Err = 0
	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error updating tracer_t.status: %v", err)
	}

	return nil
}

type guessFields []guessField

func (gf guessFields) subjectFields(sub GuessSubject) []*guessField {
	var sf []*guessField
	for i, f := range gf {
		if f.subject != sub {
			continue
		}
		sf = append(sf, &gf[i])
	}
	return sf
}

func (gf guessFields) whatField(what GuessWhat) *guessField {
	fieldIndex := slices.IndexFunc(gf, func(field guessField) bool {
		return field.what == what
	})
	if fieldIndex == -1 {
		return nil
	}

	return &gf[fieldIndex]
}

func (field *guessField) jumpPastOverlaps(subjectFields []*guessField) bool {
	overlapped := false
	for {
		// overlaps only checks for a single field overlap, so we must keep jumping until valid
		nextValid, isOverlapping := field.overlaps(subjectFields)
		if isOverlapping {
			// TODO advancing just a single offset may not be what each field needs
			// it may be multiple offsets in concert
			*field.offsetField = nextValid
			overlapped = true
			if nextValid >= field.threshold {
				return true
			}
			continue
		}
		break
	}
	return overlapped
}

func (field *guessField) overlaps(subjectFields []*guessField) (uint64, bool) {
	offset := *field.offsetField
	//log.Warnf("`%s` offset %d post", field.what, offset)
	for _, f := range subjectFields {
		if !f.finished || f.what == field.what {
			continue
		}
		soff := *f.offsetField
		size := f.valueSize
		nextValid := soff + size
		if soff <= offset && offset < nextValid {
			log.Warnf("`%s` offset %d overlapping with `%s` offset %d size %d",
				field.what, offset,
				f.what, soff, size)
			return nextValid, true
		}
	}
	return 0, false
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

	processName := filepath.Base(os.Args[0])
	if len(processName) > ProcCommMaxLen { // Truncate process name if needed
		processName = processName[:ProcCommMaxLen]
	}

	t.guessUDPv6 = cfg.CollectUDPv6Conns
	t.guessTCPv6 = cfg.CollectTCPv6Conns
	t.status = &TracerStatus{
		State: uint64(StateChecking),
		What:  uint64(GuessSAddr),
	}
	copy(t.status.Proc.Comm[:], processName)

	valuesType := reflect.TypeOf((*TracerValues)(nil)).Elem()
	valueStructField := func(name string) reflect.StructField {
		f, ok := valuesType.FieldByName(name)
		if !ok {
			panic("unable to find struct field " + name)
		}
		return f
	}

	// fields are guessed in the order of this slice
	t.guessFields = []guessField{
		{
			what:        GuessSAddr,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Saddr")},
			offsetField: &t.status.Offsets.Saddr,
		},
		{
			what:        GuessDAddr,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Daddr")},
			offsetField: &t.status.Offsets.Daddr,
		},
		{
			what:        GuessDPort,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Dport")},
			offsetField: &t.status.Offsets.Dport,
		},
		{
			what:        GuessFamily,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Family")},
			offsetField: &t.status.Offsets.Family,
			// we know the family ((struct __sk_common)->skc_family) is
			// after the skc_dport field, so we start from there
			startOffset: &t.status.Offsets.Dport,
		},
		{
			what:        GuessSPort,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Sport")},
			offsetField: &t.status.Offsets.Sport,
			// we know the sport ((struct inet_sock)->inet_sport) is
			// after the family field, so we start from there
			startOffset: &t.status.Offsets.Family,
			threshold:   thresholdInetSock,
		},
		{
			what:        GuessSAddrFl4,
			subject:     StructFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Saddr_fl4")},
			offsetField: &t.status.Offsets.Saddr_fl4,
			nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
				if !equal {
					return advanceField(4)(field, allFields, equal)
				}
				return advanceField(1)(field, allFields, equal)
			},
		},
		{
			what:        GuessDAddrFl4,
			subject:     StructFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Daddr_fl4")},
			offsetField: &t.status.Offsets.Daddr_fl4,
			nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
				if !equal {
					return advanceField(3)(field, allFields, equal)
				}
				return advanceField(1)(field, allFields, equal)
			},
		},
		{
			what:        GuessSPortFl4,
			subject:     StructFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Sport_fl4")},
			offsetField: &t.status.Offsets.Sport_fl4,
			nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
				if !equal {
					return advanceField(2)(field, allFields, equal)
				}
				return advanceField(1)(field, allFields, equal)
			},
		},
		{
			what:        GuessDPortFl4,
			subject:     StructFlowI4,
			optional:    true,
			valueFields: []reflect.StructField{valueStructField("Dport_fl4")},
			offsetField: &t.status.Offsets.Dport_fl4,
		},
	}

	if t.guessUDPv6 {
		t.guessFields = append(t.guessFields,
			guessField{
				what:        GuessSAddrFl6,
				subject:     StructFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Saddr_fl6")},
				offsetField: &t.status.Offsets.Saddr_fl6,
				nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
					if !equal {
						return advanceField(4)(field, allFields, equal)
					}
					return advanceField(1)(field, allFields, equal)
				},
			},
			guessField{
				what:        GuessDAddrFl6,
				subject:     StructFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Daddr_fl6")},
				offsetField: &t.status.Offsets.Daddr_fl6,
				nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
					if !equal {
						return advanceField(3)(field, allFields, equal)
					}
					return advanceField(1)(field, allFields, equal)
				},
			},
			guessField{
				what:        GuessSPortFl6,
				subject:     StructFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Sport_fl6")},
				offsetField: &t.status.Offsets.Sport_fl6,
				nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
					if !equal {
						return advanceField(2)(field, allFields, equal)
					}
					return advanceField(1)(field, allFields, equal)
				},
			},
			guessField{
				what:        GuessDPortFl6,
				subject:     StructFlowI6,
				optional:    true,
				valueFields: []reflect.StructField{valueStructField("Dport_fl6")},
				offsetField: &t.status.Offsets.Dport_fl6,
			},
		)
	}

	t.guessFields = append(t.guessFields,
		guessField{
			what:        GuessNetNS,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Netns")},
			offsetField: &t.status.Offsets.Netns,
			incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) {
				offsets.Ino++
				if errored || offsets.Ino >= field.threshold {
					offsets.Ino = 0
					offsets.Netns++
				}
			},
			nextFunc: func(field *guessField, allFields *guessFields, equal bool) GuessWhat {
				log.Debugf("Successfully guessed %s with offset of %d bytes", "ino", t.status.Offsets.Ino)
				return dfaultNextFunc(field, allFields, equal)
			},
		},
		guessField{
			what:        GuessRTT,
			subject:     StructSock,
			valueFields: []reflect.StructField{valueStructField("Rtt"), valueStructField("Rtt_var")},
			offsetField: &t.status.Offsets.Rtt,
			threshold:   thresholdInetSock,
			incrementFunc: func(field *guessField, offsets *TracerOffsets, _ bool) {
				// We know that these two fields are always next to each other, 4 bytes apart:
				// https://elixir.bootlin.com/linux/v4.6/source/include/linux/tcp.h#L232
				// rtt -> srtt_us
				// rtt_var -> mdev_us
				// TODO handle paired increment when overlap adjustments happen
				offsets.Rtt++
				offsets.Rtt_var = offsets.Rtt + 4
			},
		},
		guessField{
			what:        GuessSocketSK,
			subject:     StructSocket,
			valueFields: []reflect.StructField{valueStructField("Sport_via_sk"), valueStructField("Dport_via_sk")},
			valueSize:   SizeofStructSock,
			offsetField: &t.status.Offsets.Socket_sk,
		},
	)

	// if we are on kernel version < 4.7, net_dev_queue tracepoint will not be activated, and thus we should skip
	// the guessing for `struct sk_buff`
	if kv >= kv470 {
		t.guessFields = append(t.guessFields,
			guessField{
				what:        GuessSKBuffSock,
				subject:     StructSKBuff,
				valueFields: []reflect.StructField{valueStructField("Sport_via_sk_via_sk_buff"), valueStructField("Dport_via_sk_via_sk_buff")},
				valueSize:   SizeofSKBuffSock,
				offsetField: &t.status.Offsets.Sk_buff_sock,
			},
			guessField{
				what:        GuessSKBuffTransportHeader,
				subject:     StructSKBuff,
				valueSize:   SizeofSKBuffTransportHeader,
				offsetField: &t.status.Offsets.Sk_buff_transport_header,
				equalFunc: func(field *guessField, val *TracerValues, _ *TracerValues) bool {
					networkDiffFromMac := val.Network_header - val.Mac_header
					transportDiffFromNetwork := val.Transport_header - val.Network_header
					// TODO document where these values come from!
					return networkDiffFromMac == 14 && transportDiffFromNetwork == 20
				},
			},
			guessField{
				what:        GuessSKBuffHead,
				subject:     StructSKBuff,
				valueFields: []reflect.StructField{valueStructField("Sport_via_sk_buff"), valueStructField("Dport_via_sk_buff")},
				valueSize:   SizeofSKBuffHead,
				offsetField: &t.status.Offsets.Sk_buff_head,
			},
		)
	}

	if t.guessUDPv6 || t.guessTCPv6 {
		t.guessFields = append(t.guessFields,
			guessField{
				what:        GuessDAddrIPv6,
				subject:     StructSock,
				valueFields: []reflect.StructField{valueStructField("Daddr_ipv6")},
				offsetField: &t.status.Offsets.Daddr_ipv6,
			},
		)
	}

	// fixup and validate guess fields
	for i := range t.guessFields {
		f := &t.guessFields[i]
		if f.offsetField == nil {
			return nil, fmt.Errorf("guessField %s has no valid offsetField", f.what)
		}
		if f.valueSize == 0 && len(f.valueFields) > 0 {
			f.valueSize = uint64(f.valueFields[0].Type.Size())
		}
		if f.valueSize == 0 {
			return nil, fmt.Errorf("`%s` has value field size 0", f.what)
		}
		if f.threshold == 0 {
			f.threshold = threshold
		}
		if f.equalFunc == nil {
			if len(f.valueFields) == 0 {
				return nil, fmt.Errorf("`%s` needs a valid `valueFields` to use default equality function", f.what)
			}
			f.equalFunc = dfaultEqualFunc
		}
		if f.incrementFunc == nil {
			f.incrementFunc = dfaultIncrementFunc
		}
		if f.nextFunc == nil {
			f.nextFunc = dfaultNextFunc
		}
	}

	// if we already have the offsets, just return
	err = mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(t.status))
	if err == nil && State(t.status.State) == StateReady {
		return t.getConstantEditors(), nil
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
	for State(t.status.State) != StateReady {
		if err := eventGenerator.Generate(GuessWhat(t.status.What), expected); err != nil {
			return nil, err
		}

		if err := t.checkAndUpdateCurrentOffset(mp, expected, &maxRetries); err != nil {
			return nil, err
		}
	}
	log.Warnf("finished in %d iterations", t.iterations)

	return t.getConstantEditors(), nil
}

func (t *tracerOffsetGuesser) getConstantEditors() []manager.ConstantEditor {
	fl4offsets := t.guessFields.whatField(GuessSAddrFl4).finished &&
		t.guessFields.whatField(GuessDAddrFl4).finished &&
		t.guessFields.whatField(GuessSPortFl4).finished &&
		t.guessFields.whatField(GuessDPortFl4).finished
	fl6offsets := t.guessFields.whatField(GuessSAddrFl6).finished &&
		t.guessFields.whatField(GuessDAddrFl6).finished &&
		t.guessFields.whatField(GuessSPortFl6).finished &&
		t.guessFields.whatField(GuessDPortFl6).finished

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

func (t *tracerOffsetGuesser) logAndAdvance(offset uint64, next GuessWhat) error {
	guess := GuessWhat(t.status.What)
	if offset != notApplicable {
		log.Debugf("Successfully guessed `%s` with offset of %d bytes", guess, offset)
	} else {
		log.Debugf("Could not guess offset for %s", guess)
	}

	if next == GuessNotApplicable {
		t.status.State = uint64(StateReady)
		return nil
	}

	log.Debugf("Started offset guessing for %s", next)
	t.status.What = uint64(next)
	t.status.State = uint64(StateChecking)

	// check initial offset for next field and jump past overlaps
	nextField := t.guessFields.whatField(next)
	if nextField == nil {
		return fmt.Errorf("invalid offset guessing field %d", t.status.What)
	}
	if nextField.startOffset != nil {
		*nextField.offsetField = *nextField.startOffset
	}
	_ = nextField.jumpPastOverlaps(t.guessFields.subjectFields(nextField.subject))
	return nil
}
