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

type tracerOffsetGuesser struct {
	m           *manager.Manager
	status      *TracerStatus
	guessFields guessFields
	guessTCPv6  bool
	guessUDPv6  bool
	fl4offsets  bool
	fl6offsets  bool

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
	valueField := reflect.Indirect(reflect.ValueOf(val)).FieldByIndex(field.valueField.Index)
	expectedField := reflect.Indirect(reflect.ValueOf(exp)).FieldByIndex(field.valueField.Index)
	return valueField.Equal(expectedField)
}

func dfaultIncrementFunc(field *guessField, _ *TracerOffsets, _ bool) bool {
	*field.offsetField++
	return *field.offsetField < field.threshold
}

func dfaultNextFunc(field *guessField, _ bool) GuessWhat {
	return GuessWhat(int(field.what) + 1)
}

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
	valueField    reflect.StructField
	valueSize     uint64
	offsetField   *uint64
	threshold     uint64
	equalFunc     func(field *guessField, val *TracerValues, exp *TracerValues) bool
	incrementFunc func(field *guessField, offsets *TracerOffsets, errored bool) bool
	nextFunc      func(field *guessField, equal bool) GuessWhat
}

func (t *tracerOffsetGuesser) checkAndUpdateCurrentOffsetNew(mp *ebpf.Map, expected *TracerValues, maxRetries *int) error {
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
	overlapped, err := field.jumpPastOverlaps(t.guessFields.subjectFields(field.subject))
	if err != nil {
		return err
	}

	if overlapped {
		// skip to checking the newly set offset
		t.status.State = uint64(StateChecking)
		goto NextCheck
	}

	if field.equalFunc(field, &t.status.Values, expected) {
		offset := *field.offsetField
		field.finished = true
		next := field.nextFunc(field, true)
		if next == GuessNotApplicable {
			t.status.State = uint64(StateReady)
			goto NextCheck
		}

		t.logAndAdvance(offset, next)
		t.status.State = uint64(StateChecking)
		// check initial offset for next field and jump past overlaps
		nextField := t.guessFields.whatField(GuessWhat(t.status.What))
		if nextField == nil {
			return fmt.Errorf("invalid offset guessing field %d", t.status.What)
		}
		_, err := nextField.jumpPastOverlaps(t.guessFields.subjectFields(nextField.subject))
		if err != nil {
			return err
		}
		goto NextCheck
	}

	// TODO some fields don't error out, but mark fields as invalid and jump ahead
	if !field.incrementFunc(field, &t.status.Offsets, t.status.Err != 0) {
		return fmt.Errorf("overflow while guessing %s, bailing out", GuessWhat(t.status.What))
	}
	t.status.State = uint64(StateChecking)

NextCheck:
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

func (field *guessField) jumpPastOverlaps(subjectFields []*guessField) (bool, error) {
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
				return false, fmt.Errorf("overflow while guessing %s, bailing out", field.what)
			}
			continue
		}
		break
	}
	return overlapped, nil
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

// checkAndUpdateCurrentOffset checks the value for the current offset stored
// in the eBPF map against the expected value, incrementing the offset if it
// doesn't match, or going to the next field to guess if it does
func (t *tracerOffsetGuesser) checkAndUpdateCurrentOffset(mp *ebpf.Map, expected *TracerValues, maxRetries *int, threshold uint64) error {
	// get the updated map value so we can check if the current offset is
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

	switch GuessWhat(t.status.What) {
	case GuessSAddr:
		if t.status.Values.Saddr == expected.Saddr {
			t.logAndAdvance(t.status.Offsets.Saddr, GuessDAddr)
			break
		}
		t.status.Offsets.Saddr++
	case GuessDAddr:
		if t.status.Values.Daddr == expected.Daddr {
			t.logAndAdvance(t.status.Offsets.Daddr, GuessDPort)
			break
		}
		t.status.Offsets.Daddr++
	case GuessDPort:
		if t.status.Values.Dport == htons(expected.Dport) {
			t.logAndAdvance(t.status.Offsets.Dport, GuessFamily)
			// we know the family ((struct __sk_common)->skc_family) is
			// after the skc_dport field, so we start from there
			t.status.Offsets.Family = t.status.Offsets.Dport
			break
		}
		t.status.Offsets.Dport++
	case GuessFamily:
		if t.status.Values.Family == expected.Family {
			t.logAndAdvance(t.status.Offsets.Family, GuessSPort)
			// we know the sport ((struct inet_sock)->inet_sport) is
			// after the family field, so we start from there
			t.status.Offsets.Sport = t.status.Offsets.Family
			break
		}
		t.status.Offsets.Family++
	case GuessSPort:
		if t.status.Values.Sport == htons(expected.Sport) {
			t.logAndAdvance(t.status.Offsets.Sport, GuessSAddrFl4)
			break
		}
		t.status.Offsets.Sport++
	case GuessSAddrFl4:
		if t.status.Values.Saddr_fl4 == expected.Saddr_fl4 {
			t.logAndAdvance(t.status.Offsets.Saddr_fl4, GuessDAddrFl4)
			break
		}
		t.status.Offsets.Saddr_fl4++
		if t.status.Offsets.Saddr_fl4 >= threshold {
			// Let's skip all other flowi4 fields
			t.logAndAdvance(notApplicable, t.flowi6EntryState())
			t.fl4offsets = false
			break
		}
	case GuessDAddrFl4:
		if t.status.Values.Daddr_fl4 == expected.Daddr_fl4 {
			t.logAndAdvance(t.status.Offsets.Daddr_fl4, GuessSPortFl4)
			break
		}
		t.status.Offsets.Daddr_fl4++
		if t.status.Offsets.Daddr_fl4 >= threshold {
			t.logAndAdvance(notApplicable, t.flowi6EntryState())
			t.fl4offsets = false
			break
		}
	case GuessSPortFl4:
		if t.status.Values.Sport_fl4 == htons(expected.Sport_fl4) {
			t.logAndAdvance(t.status.Offsets.Sport_fl4, GuessDPortFl4)
			break
		}
		t.status.Offsets.Sport_fl4++
		if t.status.Offsets.Sport_fl4 >= threshold {
			t.logAndAdvance(notApplicable, t.flowi6EntryState())
			t.fl4offsets = false
			break
		}
	case GuessDPortFl4:
		if t.status.Values.Dport_fl4 == htons(expected.Dport_fl4) {
			t.logAndAdvance(t.status.Offsets.Dport_fl4, t.flowi6EntryState())
			t.fl4offsets = true
			break
		}
		t.status.Offsets.Dport_fl4++
		if t.status.Offsets.Dport_fl4 >= threshold {
			t.logAndAdvance(notApplicable, t.flowi6EntryState())
			t.fl4offsets = false
			break
		}
	case GuessSAddrFl6:
		if compareIPv6(t.status.Values.Saddr_fl6, expected.Saddr_fl6) {
			t.logAndAdvance(t.status.Offsets.Saddr_fl6, GuessDAddrFl6)
			break
		}
		t.status.Offsets.Saddr_fl6++
		if t.status.Offsets.Saddr_fl6 >= threshold {
			// Let's skip all other flowi6 fields
			t.logAndAdvance(notApplicable, GuessNetNS)
			t.fl6offsets = false
			break
		}
	case GuessDAddrFl6:
		if compareIPv6(t.status.Values.Daddr_fl6, expected.Daddr_fl6) {
			t.logAndAdvance(t.status.Offsets.Daddr_fl6, GuessSPortFl6)
			break
		}
		t.status.Offsets.Daddr_fl6++
		if t.status.Offsets.Daddr_fl6 >= threshold {
			t.logAndAdvance(notApplicable, GuessNetNS)
			t.fl6offsets = false
			break
		}
	case GuessSPortFl6:
		if t.status.Values.Sport_fl6 == htons(expected.Sport_fl6) {
			t.logAndAdvance(t.status.Offsets.Sport_fl6, GuessDPortFl6)
			break
		}
		t.status.Offsets.Sport_fl6++
		if t.status.Offsets.Sport_fl6 >= threshold {
			t.logAndAdvance(notApplicable, GuessNetNS)
			t.fl6offsets = false
			break
		}
	case GuessDPortFl6:
		if t.status.Values.Dport_fl6 == htons(expected.Dport_fl6) {
			t.logAndAdvance(t.status.Offsets.Dport_fl6, GuessNetNS)
			t.fl6offsets = true
			break
		}
		t.status.Offsets.Dport_fl6++
		if t.status.Offsets.Dport_fl6 >= threshold {
			t.logAndAdvance(notApplicable, GuessNetNS)
			t.fl6offsets = false
			break
		}
	case GuessNetNS:
		if t.status.Values.Netns == expected.Netns {
			t.logAndAdvance(t.status.Offsets.Netns, GuessRTT)
			log.Debugf("Successfully guessed %v with offset of %d bytes", "ino", t.status.Offsets.Ino)
			break
		}
		t.status.Offsets.Ino++
		// go to the next offset_netns if we get an error
		if t.status.Err != 0 || t.status.Offsets.Ino >= threshold {
			t.status.Offsets.Ino = 0
			t.status.Offsets.Netns++
		}
	case GuessRTT:
		// For more information on the bit shift operations see:
		// https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
		if t.status.Values.Rtt>>3 == expected.Rtt && t.status.Values.Rtt_var>>2 == expected.Rtt_var {
			t.logAndAdvance(t.status.Offsets.Rtt, GuessSocketSK)
			break
		}
		// We know that these two fields are always next to each other, 4 bytes apart:
		// https://elixir.bootlin.com/linux/v4.6/source/include/linux/tcp.h#L232
		// rtt -> srtt_us
		// rtt_var -> mdev_us
		t.status.Offsets.Rtt++
		t.status.Offsets.Rtt_var = t.status.Offsets.Rtt + 4

	case GuessSocketSK:
		if t.status.Values.Sport_via_sk == htons(expected.Sport) && t.status.Values.Dport_via_sk == htons(expected.Dport) {
			// if we are on kernel version < 4.7, net_dev_queue tracepoint will not be activated, and thus we should skip
			// the guessing for `struct sk_buff`
			next := GuessSKBuffSock
			kv, err := kernel.HostVersion()
			if err != nil {
				return fmt.Errorf("error getting kernel version: %w", err)
			}
			kv470 := kernel.VersionCode(4, 7, 0)

			// if IPv6 enabled & kv lower than 4.7.0, skip guessing for some fields
			if (t.guessTCPv6 || t.guessUDPv6) && kv < kv470 {
				next = GuessDAddrIPv6
			}

			// if both IPv6 disabled and kv lower than 4.7.0, skip to the end
			if !t.guessTCPv6 && !t.guessUDPv6 && kv < kv470 {
				t.logAndAdvance(t.status.Offsets.Socket_sk, GuessNotApplicable)
				return t.setReadyState(mp)
			}

			t.logAndAdvance(t.status.Offsets.Socket_sk, next)
			break
		}
		t.status.Offsets.Socket_sk++
	case GuessSKBuffSock:
		if t.status.Values.Sport_via_sk_via_sk_buff == htons(expected.Sport_fl4) && t.status.Values.Dport_via_sk_via_sk_buff == htons(expected.Dport_fl4) {
			t.logAndAdvance(t.status.Offsets.Sk_buff_sock, GuessSKBuffTransportHeader)
			break
		}
		t.status.Offsets.Sk_buff_sock++
	case GuessSKBuffTransportHeader:
		networkDiffFromMac := t.status.Values.Network_header - t.status.Values.Mac_header
		transportDiffFromNetwork := t.status.Values.Transport_header - t.status.Values.Network_header
		if networkDiffFromMac == 14 && transportDiffFromNetwork == 20 {
			t.logAndAdvance(t.status.Offsets.Sk_buff_transport_header, GuessSKBuffHead)
			break
		}
		t.status.Offsets.Sk_buff_transport_header++
	case GuessSKBuffHead:
		if t.status.Values.Sport_via_sk_via_sk_buff == htons(expected.Sport_fl4) && t.status.Values.Dport_via_sk_via_sk_buff == htons(expected.Dport_fl4) {
			if !t.guessTCPv6 && !t.guessUDPv6 {
				t.logAndAdvance(t.status.Offsets.Sk_buff_head, GuessNotApplicable)
				return t.setReadyState(mp)
			} else {
				t.logAndAdvance(t.status.Offsets.Sk_buff_head, GuessDAddrIPv6)
				break
			}
		}
		t.status.Offsets.Sk_buff_head++
	case GuessDAddrIPv6:
		if compareIPv6(t.status.Values.Daddr_ipv6, expected.Daddr_ipv6) {
			t.logAndAdvance(t.status.Offsets.Daddr_ipv6, GuessNotApplicable)
			// at this point, we've guessed all the offsets we need,
			// set the t.status to "stateReady"
			return t.setReadyState(mp)
		}
		t.status.Offsets.Daddr_ipv6++
	default:
		return fmt.Errorf("unexpected field to guess: %s", GuessWhat(t.status.What))
	}

	t.status.State = uint64(StateChecking)
	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error updating tracer_t.status: %v", err)
	}

	return nil
}

func (t *tracerOffsetGuesser) setReadyState(mp *ebpf.Map) error {
	t.status.State = uint64(StateReady)
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error updating tracer_status: %v", err)
	}
	return nil
}

func (t *tracerOffsetGuesser) flowi6EntryState() GuessWhat {
	if !t.guessUDPv6 {
		return GuessNetNS
	}
	return GuessSAddrFl6
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

	// order here is not important, default nextFunc uses GuessWhat ordering
	t.guessFields = []guessField{
		{
			what:        GuessSAddr,
			subject:     StructSock,
			valueField:  valueStructField("Saddr"),
			offsetField: &t.status.Offsets.Saddr,
		},
		{
			what:        GuessDAddr,
			subject:     StructSock,
			valueField:  valueStructField("Daddr"),
			offsetField: &t.status.Offsets.Daddr,
		},
		{
			what:        GuessDPort,
			subject:     StructSock,
			valueField:  valueStructField("Dport"),
			offsetField: &t.status.Offsets.Dport,
			incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
				offsets.Dport++
				// we know the family ((struct __sk_common)->skc_family) is
				// after the skc_dport field, so we start from there
				offsets.Family++
				return offsets.Dport < field.threshold
			},
		},
		{
			what:        GuessFamily,
			subject:     StructSock,
			valueField:  valueStructField("Family"),
			offsetField: &t.status.Offsets.Family,
			incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
				offsets.Family++
				// we know the sport ((struct inet_sock)->inet_sport) is
				// after the family field, so we start from there
				offsets.Sport++
				return offsets.Family < field.threshold
			},
		},
		{
			what:        GuessSPort,
			subject:     StructSock,
			valueField:  valueStructField("Sport"),
			offsetField: &t.status.Offsets.Sport,
			threshold:   thresholdInetSock,
		},
		// TODO handle custom next logic if fl4/6 errors or IPv6 is disabled
		{
			what:        GuessSAddrFl4,
			subject:     StructFlowI4,
			valueField:  valueStructField("Saddr_fl4"),
			offsetField: &t.status.Offsets.Saddr_fl4,
		},
		{
			what:        GuessDAddrFl4,
			subject:     StructFlowI4,
			valueField:  valueStructField("Daddr_fl4"),
			offsetField: &t.status.Offsets.Daddr_fl4,
		},
		{
			what:        GuessSPortFl4,
			subject:     StructFlowI4,
			valueField:  valueStructField("Sport_fl4"),
			offsetField: &t.status.Offsets.Sport_fl4,
		},
		{
			what:        GuessDPortFl4,
			subject:     StructFlowI4,
			valueField:  valueStructField("Dport_fl4"),
			offsetField: &t.status.Offsets.Dport_fl4,
		},
	}
	if t.guessUDPv6 {
		t.guessFields = append(t.guessFields,
			guessField{
				what:        GuessSAddrFl6,
				subject:     StructFlowI6,
				valueField:  valueStructField("Saddr_fl6"),
				offsetField: &t.status.Offsets.Saddr_fl6,
			},
			guessField{
				what:        GuessDAddrFl6,
				subject:     StructFlowI6,
				valueField:  valueStructField("Daddr_fl6"),
				offsetField: &t.status.Offsets.Daddr_fl6,
			},
			guessField{
				what:        GuessSPortFl6,
				subject:     StructFlowI6,
				valueField:  valueStructField("Sport_fl6"),
				offsetField: &t.status.Offsets.Sport_fl6,
			},
			guessField{
				what:        GuessDPortFl6,
				subject:     StructFlowI6,
				valueField:  valueStructField("Dport_fl6"),
				offsetField: &t.status.Offsets.Dport_fl6,
			})
	}

	t.guessFields = append(t.guessFields,
		guessField{
			what:        GuessNetNS,
			subject:     StructSock,
			valueField:  valueStructField("Netns"),
			offsetField: &t.status.Offsets.Netns,
			incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
				offsets.Ino++
				if errored || offsets.Ino >= field.threshold {
					offsets.Ino = 0
					offsets.Netns++
				}
				return offsets.Netns < field.threshold
			},
		},
		guessField{
			what:        GuessRTT,
			subject:     StructSock,
			valueField:  valueStructField("Rtt"),
			offsetField: &t.status.Offsets.Rtt,
			threshold:   thresholdInetSock,
			equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
				return val.Rtt == exp.Rtt && val.Rtt_var == exp.Rtt_var
			},
			incrementFunc: func(field *guessField, offsets *TracerOffsets, _ bool) bool {
				// We know that these two fields are always next to each other, 4 bytes apart:
				// https://elixir.bootlin.com/linux/v4.6/source/include/linux/tcp.h#L232
				// rtt -> srtt_us
				// rtt_var -> mdev_us
				offsets.Rtt++
				offsets.Rtt_var = offsets.Rtt + 4
				return offsets.Rtt < field.threshold
			},
		},
		guessField{
			what:        GuessSocketSK,
			subject:     StructSocket,
			valueSize:   SizeofStructSock,
			offsetField: &t.status.Offsets.Socket_sk,
			equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
				// TODO handle custom next logic
				return val.Sport_via_sk == exp.Sport_via_sk &&
					val.Dport_via_sk == exp.Dport_via_sk
			},
		},
		guessField{
			what:        GuessSKBuffSock,
			subject:     StructSKBuff,
			valueSize:   SizeofSKBuffSock,
			offsetField: &t.status.Offsets.Sk_buff_sock,
			equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
				return val.Sport_via_sk_via_sk_buff == exp.Sport_via_sk_via_sk_buff &&
					val.Dport_via_sk_via_sk_buff == exp.Dport_via_sk_via_sk_buff
			},
		},
		guessField{
			what:        GuessSKBuffTransportHeader,
			subject:     StructSKBuff,
			valueSize:   SizeofSKBuffTransportHeader,
			offsetField: &t.status.Offsets.Sk_buff_transport_header,
			equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
				networkDiffFromMac := val.Network_header - val.Mac_header
				transportDiffFromNetwork := val.Transport_header - val.Network_header
				// TODO document where these values come from!
				return networkDiffFromMac == 14 && transportDiffFromNetwork == 20
			},
		},
		guessField{
			// TODO handle custom next logic
			what:        GuessSKBuffHead,
			subject:     StructSKBuff,
			valueSize:   SizeofSKBuffHead,
			offsetField: &t.status.Offsets.Sk_buff_head,
			equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
				return val.Sport_via_sk_buff == exp.Sport_via_sk_buff &&
					val.Dport_via_sk_buff == exp.Dport_via_sk_buff
			},
		},
		guessField{
			what:        GuessDAddrIPv6,
			subject:     StructSock,
			valueField:  valueStructField("Daddr_ipv6"),
			offsetField: &t.status.Offsets.Daddr_ipv6,
			nextFunc: func(field *guessField, _ bool) GuessWhat {
				return GuessNotApplicable
			},
		})

	// fixup and validate guess fields
	for i := range t.guessFields {
		f := &t.guessFields[i]
		if f.offsetField == nil {
			return nil, fmt.Errorf("guessField %s has no valid offsetField", f.what)
		}
		if f.valueField.Name != "" {
			f.valueSize = uint64(f.valueField.Type.Size())
		}
		if f.valueSize == 0 {
			return nil, fmt.Errorf("`%s` has value field size 0", f.what)
		}
		if f.threshold == 0 {
			f.threshold = threshold
		}
		if f.equalFunc == nil {
			if f.valueField.Name == "" {
				return nil, fmt.Errorf("`%s` needs a valid `valueField` to use default equality function", f.what)
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

		if err := t.checkAndUpdateCurrentOffsetNew(mp, expected, &maxRetries); err != nil {
			return nil, err
		}

		// Stop at a reasonable offset so we don't run forever.
		// Reading too far away in kernel memory is not a big deal:
		// probe_kernel_read() handles faults gracefully.
		//if t.status.Offsets.Saddr >= threshold || t.status.Offsets.Daddr >= threshold ||
		//	t.status.Offsets.Sport >= thresholdInetSock || t.status.Offsets.Dport >= threshold ||
		//	t.status.Offsets.Netns >= threshold || t.status.Offsets.Family >= threshold ||
		//	t.status.Offsets.Daddr_ipv6 >= threshold || t.status.Offsets.Rtt >= thresholdInetSock ||
		//	t.status.Offsets.Socket_sk >= threshold || t.status.Offsets.Sk_buff_sock >= threshold ||
		//	t.status.Offsets.Sk_buff_transport_header >= threshold || t.status.Offsets.Sk_buff_head >= threshold {
		//	return nil, fmt.Errorf("overflow while guessing %v, bailing out", GuessWhat(t.status.What))
		//}
	}
	log.Warnf("finished in %d iterations", t.iterations)

	return t.getConstantEditors(), nil
}

func (t *tracerOffsetGuesser) getConstantEditors() []manager.ConstantEditor {
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
		boolConst("fl4_offsets", t.fl4offsets),
		{Name: "offset_saddr_fl6", Value: t.status.Offsets.Saddr_fl6},
		{Name: "offset_daddr_fl6", Value: t.status.Offsets.Daddr_fl6},
		{Name: "offset_sport_fl6", Value: t.status.Offsets.Sport_fl6},
		{Name: "offset_dport_fl6", Value: t.status.Offsets.Dport_fl6},
		boolConst("fl6_offsets", t.fl6offsets),
		{Name: "offset_socket_sk", Value: t.status.Offsets.Socket_sk},
		{Name: "offset_sk_buff_sock", Value: t.status.Offsets.Sk_buff_sock},
		{Name: "offset_sk_buff_transport_header", Value: t.status.Offsets.Sk_buff_transport_header},
		{Name: "offset_sk_buff_head", Value: t.status.Offsets.Sk_buff_head},
	}
}

func (t *tracerOffsetGuesser) logAndAdvance(offset uint64, next GuessWhat) {
	guess := GuessWhat(t.status.What)
	if offset != notApplicable {
		log.Debugf("Successfully guessed %s with offset of %d bytes", guess, offset)
	} else {
		log.Debugf("Could not guess offset for %s", guess)
	}
	if next != GuessNotApplicable {
		log.Debugf("Started offset guessing for %s", next)
		t.status.What = uint64(next)
	}
}
