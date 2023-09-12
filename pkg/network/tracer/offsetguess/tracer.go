// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package offsetguess

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/native"
)

const InterfaceLocalMulticastIPv6 = "ff01::1"
const listenIPv4 = "127.0.0.2"

const (
	tcpGetSockOptKProbeNotCalled uint64 = 0
	tcpGetSockOptKProbeCalled    uint64 = 1
)

var tcpKprobeCalledString = map[uint64]string{
	tcpGetSockOptKProbeNotCalled: "tcp_getsockopt kprobe not executed",
	tcpGetSockOptKProbeCalled:    "tcp_getsockopt kprobe executed",
}

type tracerOffsetGuesser struct {
	m               *manager.Manager
	status          *TracerStatus
	dfaultThreshold uint64
	guessTCPv6      bool
	guessUDPv6      bool
	fl4offsets      bool
	fl6offsets      bool
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

func extractIPsAndPorts(conn net.Conn) (
	saddr, daddr uint32,
	sport, dport uint16,
	err error,
) {
	saddrStr, sportStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return
	}
	saddr = native.Endian.Uint32(net.ParseIP(saddrStr).To4())
	sportn, err := strconv.Atoi(sportStr)
	if err != nil {
		return
	}
	sport = uint16(sportn)

	daddrStr, dportStr, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	daddr = native.Endian.Uint32(net.ParseIP(daddrStr).To4())
	dportn, err := strconv.Atoi(dportStr)
	if err != nil {
		return
	}

	dport = uint16(dportn)
	return
}

func extractIPv6AddressAndPort(addr net.Addr) (ip [4]uint32, port uint16, err error) {
	udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
	if err != nil {
		return
	}

	ip, err = uint32ArrayFromIPv6(udpAddr.IP)
	if err != nil {
		return
	}
	port = uint16(udpAddr.Port)

	return
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

func compareIPv6(a [4]uint32, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func htons(a uint16) uint16 {
	var arr [2]byte
	binary.BigEndian.PutUint16(arr[:], a)
	return native.Endian.Uint16(arr[:])
}

func generateRandomIPv6Address() net.IP {
	// multicast (ff00::/8) or link-local (fe80::/10) addresses don't work for
	// our purposes so let's choose a "random number" for the first 32 bits.
	//
	// chosen by fair dice roll.
	// guaranteed to be random.
	// https://xkcd.com/221/
	base := []byte{0x87, 0x58, 0x60, 0x31}
	addr := make([]byte, 16)
	copy(addr, base)
	_, err := rand.Read(addr[4:])
	if err != nil {
		panic(err)
	}

	return addr
}

func uint32ArrayFromIPv6(ip net.IP) (addr [4]uint32, err error) {
	buf := []byte(ip)
	if len(buf) < 15 {
		err = fmt.Errorf("invalid IPv6 address byte length %d", len(buf))
		return
	}

	addr[0] = native.Endian.Uint32(buf[0:4])
	addr[1] = native.Endian.Uint32(buf[4:8])
	addr[2] = native.Endian.Uint32(buf[8:12])
	addr[3] = native.Endian.Uint32(buf[12:16])
	return
}

func GetIPv6LinkLocalAddress() ([]*net.UDPAddr, error) {
	ints, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var udpAddrs []*net.UDPAddr
	for _, i := range ints {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if strings.HasPrefix(a.String(), "fe80::") && !strings.HasPrefix(i.Name, "dummy") {
				// this address *may* have CIDR notation
				if ar, _, err := net.ParseCIDR(a.String()); err == nil {
					udpAddrs = append(udpAddrs, &net.UDPAddr{IP: ar, Zone: i.Name})
					continue
				}
				udpAddrs = append(udpAddrs, &net.UDPAddr{IP: net.ParseIP(a.String()), Zone: i.Name})
			}
		}
	}
	if len(udpAddrs) > 0 {
		return udpAddrs, nil
	}
	return nil, fmt.Errorf("no IPv6 link local address found")
}

func dfaultEqualFunc(field *guessField, val *TracerValues, exp *TracerValues) bool {
	valueField := reflect.Indirect(reflect.ValueOf(val)).Field(field.valueFieldIndex)
	expectedField := reflect.Indirect(reflect.ValueOf(exp)).Field(field.valueFieldIndex)
	return valueField.Equal(expectedField)
}

func dfaultIncrementFunc(field *guessField, offsets *TracerOffsets, _ bool) bool {
	idx := field.valueFieldIndex
	if field.offsetFieldIndex > 0 {
		idx = field.offsetFieldIndex
	}

	offsetField := reflect.Indirect(reflect.ValueOf(offsets)).Field(idx)
	offset := offsetField.Uint()
	offset++
	offsetField.SetUint(offset)
	return offset < field.threshold
}

func dfaultNextFunc(field *guessField) GuessWhat {
	return GuessWhat(int(field.what) + 1)
}

type guessField struct {
	what             GuessWhat
	valueFieldIndex  int
	offsetFieldIndex int
	threshold        uint64
	equalFunc        func(field *guessField, val *TracerValues, exp *TracerValues) bool
	incrementFunc    func(field *guessField, offsets *TracerOffsets, errored bool) bool
	nextFunc         func(field *guessField) GuessWhat
}

// order here is not important, default nextFunc uses GuessWhat ordering
var guessFields = []guessField{
	{what: GuessSAddr, valueFieldIndex: 0},
	{what: GuessDAddr, valueFieldIndex: 1},
	{
		what:            GuessDPort,
		valueFieldIndex: 3,
		incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
			offsets.Dport++
			// we know the family ((struct __sk_common)->skc_family) is
			// after the skc_dport field, so we start from there
			offsets.Family++
			return offsets.Dport < field.threshold
		},
	},
	{
		what:             GuessFamily,
		valueFieldIndex:  5,
		offsetFieldIndex: 6,
		incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
			offsets.Family++
			// we know the sport ((struct inet_sock)->inet_sport) is
			// after the family field, so we start from there
			offsets.Sport++
			return offsets.Family < field.threshold
		},
	},
	{what: GuessSPort, valueFieldIndex: 2, threshold: thresholdInetSock},
	// TODO handle custom next logic if fl4/6 errors or IPv6 is disabled
	{what: GuessSAddrFl4, valueFieldIndex: 9, offsetFieldIndex: 10},
	{what: GuessDAddrFl4, valueFieldIndex: 10, offsetFieldIndex: 11},
	{what: GuessSPortFl4, valueFieldIndex: 11, offsetFieldIndex: 12},
	{what: GuessDPortFl4, valueFieldIndex: 12, offsetFieldIndex: 13},
	{what: GuessSAddrFl6, valueFieldIndex: 13, offsetFieldIndex: 14},
	{what: GuessDAddrFl6, valueFieldIndex: 14, offsetFieldIndex: 15},
	{what: GuessSPortFl6, valueFieldIndex: 15, offsetFieldIndex: 16},
	{what: GuessDPortFl6, valueFieldIndex: 16, offsetFieldIndex: 17},
	{
		what:            GuessNetNS,
		valueFieldIndex: 4,
		incrementFunc: func(field *guessField, offsets *TracerOffsets, errored bool) bool {
			offsets.Ino++
			if errored || offsets.Ino >= field.threshold {
				offsets.Ino = 0
				offsets.Netns++
			}
			return offsets.Netns < field.threshold
		},
	},
	{
		what:             GuessRTT,
		valueFieldIndex:  6,
		offsetFieldIndex: 7,
		threshold:        thresholdInetSock,
		equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
			// For more information on the bit shift operations see:
			// https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
			return val.Rtt>>3 == exp.Rtt && val.Rtt_var>>2 == exp.Rtt_var
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
	{
		what:             GuessSocketSK,
		offsetFieldIndex: 18,
		equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
			// TODO handle custom next logic
			return val.Sport_via_sk == exp.Sport_via_sk &&
				val.Dport_via_sk == exp.Dport_via_sk
		},
	},
	{
		what:             GuessSKBuffSock,
		offsetFieldIndex: 19,
		equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
			return val.Sport_via_sk_via_sk_buff == exp.Sport_via_sk_via_sk_buff &&
				val.Dport_via_sk_via_sk_buff == exp.Dport_via_sk_via_sk_buff
		},
	},
	{
		what:             GuessSKBuffTransportHeader,
		offsetFieldIndex: 20,
		equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
			networkDiffFromMac := val.Network_header - val.Mac_header
			transportDiffFromNetwork := val.Transport_header - val.Network_header
			// TODO document where these values come from!
			return networkDiffFromMac == 14 && transportDiffFromNetwork == 20
		},
	},
	{
		// TODO handle custom next logic
		what:             GuessSKBuffHead,
		offsetFieldIndex: 21,
		equalFunc: func(field *guessField, val *TracerValues, exp *TracerValues) bool {
			return val.Sport_via_sk_buff == exp.Sport_via_sk_buff &&
				val.Dport_via_sk_buff == exp.Dport_via_sk_buff
		},
	},
	{
		what:             GuessDAddrIPv6,
		valueFieldIndex:  8,
		offsetFieldIndex: 9,
		nextFunc: func(field *guessField) GuessWhat {
			return GuessNotApplicable
		},
	},
}

func (t *tracerOffsetGuesser) checkAndUpdateCurrentOffsetNew(mp *ebpf.Map, expected *TracerValues, maxRetries *int, threshold uint64) error {
	// get the updated map value, so we can check if the current offset is
	// the right one
	if err := mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error reading tracer_status: %v", err)
	}

	if State(t.status.State) != StateChecked {
		if *maxRetries == 0 {
			return fmt.Errorf("invalid guessing state while guessing %v, got %v expected %v. %v",
				whatString[GuessWhat(t.status.What)], stateString[State(t.status.State)], stateString[StateChecked], tcpKprobeCalledString[t.status.Info_kprobe_status])
		}
		*maxRetries--
		time.Sleep(10 * time.Millisecond)
		return nil
	}
	//log.Warnf("what: %s\noffsets: %+v\nval: %+v\nexp: %+v", whatString[GuessWhat(t.status.What)], t.status.Offsets, &t.status.Values, expected)

	fieldIndex := slices.IndexFunc(guessFields, func(field guessField) bool {
		return field.what == GuessWhat(t.status.What)
	})
	if fieldIndex == -1 {
		return fmt.Errorf("invalid offset guessing field %d", t.status.What)
	}

	field := guessFields[fieldIndex]
	if field.threshold == 0 {
		field.threshold = t.dfaultThreshold
	}

	equalFunc := dfaultEqualFunc
	incrementFunc := dfaultIncrementFunc
	nextFunc := dfaultNextFunc
	if field.equalFunc != nil {
		equalFunc = field.equalFunc
	}
	if field.incrementFunc != nil {
		incrementFunc = field.incrementFunc
	}
	if field.nextFunc != nil {
		nextFunc = field.nextFunc
	}

	if equalFunc(&field, &t.status.Values, expected) {
		offset := reflect.ValueOf(t.status.Offsets).Field(field.valueFieldIndex).Uint()
		next := nextFunc(&field)
		if next == GuessNotApplicable {
			t.status.State = uint64(StateReady)
		} else {
			t.logAndAdvance(offset, next)
			t.status.State = uint64(StateChecking)
		}
	} else {
		// TODO some fields don't error out, but mark fields as invalid and jump ahead
		if !incrementFunc(&field, &t.status.Offsets, t.status.Err != 0) {
			return fmt.Errorf("overflow while guessing %v, bailing out", whatString[GuessWhat(t.status.What)])
		}
		t.status.State = uint64(StateChecking)
	}

	t.status.Err = 0
	//log.Warnf("after: %+v", t.status)
	// update the map with the new offset/field to check
	if err := mp.Put(unsafe.Pointer(&zero), unsafe.Pointer(t.status)); err != nil {
		return fmt.Errorf("error updating tracer_t.status: %v", err)
	}

	return nil
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
			return fmt.Errorf("invalid guessing state while guessing %v, got %v expected %v. %v",
				whatString[GuessWhat(t.status.What)], stateString[State(t.status.State)], stateString[StateChecked], tcpKprobeCalledString[t.status.Info_kprobe_status])
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
		return fmt.Errorf("unexpected field to guess: %v", whatString[GuessWhat(t.status.What)])
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
	t.dfaultThreshold = cfg.OffsetGuessThreshold

	// pid & tid must not change during the guessing work: the communication
	// between ebpf and userspace relies on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	processName := filepath.Base(os.Args[0])
	if len(processName) > ProcCommMaxLen { // Truncate process name if needed
		processName = processName[:ProcCommMaxLen]
	}

	cProcName := [ProcCommMaxLen + 1]int8{} // Last char has to be null character, so add one
	for i, ch := range processName {
		cProcName[i] = int8(ch)
	}

	t.guessUDPv6 = cfg.CollectUDPv6Conns
	t.guessTCPv6 = cfg.CollectTCPv6Conns
	t.status = &TracerStatus{
		State: uint64(StateChecking),
		Proc:  Proc{Comm: cProcName},
		What:  uint64(GuessSAddr),
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

		if err := t.checkAndUpdateCurrentOffsetNew(mp, expected, &maxRetries, threshold); err != nil {
			return nil, err
		}

		// Stop at a reasonable offset so we don't run forever.
		// Reading too far away in kernel memory is not a big deal:
		// probe_kernel_read() handles faults gracefully.
		if t.status.Offsets.Saddr >= threshold || t.status.Offsets.Daddr >= threshold ||
			t.status.Offsets.Sport >= thresholdInetSock || t.status.Offsets.Dport >= threshold ||
			t.status.Offsets.Netns >= threshold || t.status.Offsets.Family >= threshold ||
			t.status.Offsets.Daddr_ipv6 >= threshold || t.status.Offsets.Rtt >= thresholdInetSock ||
			t.status.Offsets.Socket_sk >= threshold || t.status.Offsets.Sk_buff_sock >= threshold ||
			t.status.Offsets.Sk_buff_transport_header >= threshold || t.status.Offsets.Sk_buff_head >= threshold {
			return nil, fmt.Errorf("overflow while guessing %v, bailing out", whatString[GuessWhat(t.status.What)])
		}
	}

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

type tracerEventGenerator struct {
	listener net.Listener
	conn     net.Conn
	udpConn  net.Conn
	udp6Conn *net.UDPConn
	udpDone  func()
}

func newTracerEventGenerator(flowi6 bool) (*tracerEventGenerator, error) {
	eg := &tracerEventGenerator{}

	// port 0 means we let the kernel choose a free port
	var err error
	addr := fmt.Sprintf("%s:0", listenIPv4)
	eg.listener, err = net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}

	go acceptHandler(eg.listener)

	// Spin up UDP server
	var udpAddr string
	udpAddr, eg.udpDone, err = newUDPServer(addr)
	if err != nil {
		eg.Close()
		return nil, err
	}

	// Establish connection that will be used in the offset guessing
	eg.conn, err = net.Dial(eg.listener.Addr().Network(), eg.listener.Addr().String())
	if err != nil {
		eg.Close()
		return nil, err
	}

	eg.udpConn, err = net.Dial("udp", udpAddr)
	if err != nil {
		eg.Close()
		return nil, err
	}

	eg.udp6Conn, err = getUDP6Conn(flowi6)
	if err != nil {
		eg.Close()
		return nil, err
	}

	return eg, nil
}

func getUDP6Conn(flowi6 bool) (*net.UDPConn, error) {
	if !flowi6 {
		return nil, nil
	}

	linkLocals, err := GetIPv6LinkLocalAddress()
	if err != nil {
		// TODO: Find a offset guessing method that doesn't need an available IPv6 interface
		log.Debugf("unable to find ipv6 device for udp6 flow offset guessing. unconnected udp6 flows won't be traced: %s", err)
		return nil, nil
	}
	var conn *net.UDPConn
	for _, linkLocalAddr := range linkLocals {
		conn, err = net.ListenUDP("udp6", linkLocalAddr)
		if err == nil {
			log.Warnf("offset guessing: local udp v6 conn: local addr %s", conn.LocalAddr())
			return conn, err
		}
	}
	return nil, err
}

// Generate an event for offset guessing
func (e *tracerEventGenerator) Generate(status GuessWhat, expected *TracerValues) error {
	// Are we guessing the IPv6 field?
	if status == GuessDAddrIPv6 {
		// For ipv6, we don't need the source port because we already guessed it doing ipv4 connections so
		// we use a random destination address and try to connect to it.
		var err error
		addr := generateRandomIPv6Address()
		expected.Daddr_ipv6, err = uint32ArrayFromIPv6(addr)
		if err != nil {
			return err
		}

		bindAddress := fmt.Sprintf("[%s]:9092", addr.String())

		// Since we connect to a random IP, this will most likely fail. In the unlikely case where it connects
		// successfully, we close the connection to avoid a leak.
		if conn, err := net.DialTimeout("tcp6", bindAddress, 10*time.Millisecond); err == nil {
			conn.Close()
		}

		return nil
	} else if status == GuessSAddrFl4 ||
		status == GuessDAddrFl4 ||
		status == GuessSPortFl4 ||
		status == GuessDPortFl4 ||
		status == GuessSKBuffSock ||
		status == GuessSKBuffTransportHeader ||
		status == GuessSKBuffHead {
		payload := []byte("test")
		_, err := e.udpConn.Write(payload)

		return err
	} else if e.udp6Conn != nil &&
		(status == GuessSAddrFl6 ||
			status == GuessDAddrFl6 ||
			status == GuessSPortFl6 ||
			status == GuessDPortFl6) {
		payload := []byte("test")
		remoteAddr := &net.UDPAddr{IP: net.ParseIP(InterfaceLocalMulticastIPv6), Port: 53}
		_, err := e.udp6Conn.WriteTo(payload, remoteAddr)
		if err != nil {
			return err
		}

		expected.Daddr_fl6, err = uint32ArrayFromIPv6(remoteAddr.IP)
		if err != nil {
			return err
		}
		expected.Dport_fl6 = uint16(remoteAddr.Port)

		return nil
	}

	// This triggers the KProbe handler attached to `tcp_getsockopt`
	_, err := TcpGetInfo(e.conn)
	return err
}

func (e *tracerEventGenerator) populateUDPExpectedValues(expected *TracerValues) error {
	saddr, daddr, sport, dport, err := extractIPsAndPorts(e.udpConn)
	if err != nil {
		return err
	}
	expected.Saddr_fl4 = saddr
	expected.Sport_fl4 = sport
	expected.Sport_via_sk_via_sk_buff = sport
	expected.Sport_via_sk_buff = sport
	expected.Daddr_fl4 = daddr
	expected.Dport_fl4 = dport
	expected.Dport_via_sk_via_sk_buff = dport
	expected.Dport_via_sk_buff = dport

	if e.udp6Conn != nil {
		saddr6, sport6, err := extractIPv6AddressAndPort(e.udp6Conn.LocalAddr())
		if err != nil {
			return err
		}
		expected.Saddr_fl6 = saddr6
		expected.Sport_fl6 = sport6
	}

	return nil
}

func (e *tracerEventGenerator) Close() {
	if e.conn != nil {
		e.conn.Close()
	}

	if e.listener != nil {
		_ = e.listener.Close()
	}

	if e.udpConn != nil {
		_ = e.udpConn.Close()
	}

	if e.udp6Conn != nil {
		_ = e.udp6Conn.Close()
	}

	if e.udpDone != nil {
		e.udpDone()
	}
}

func acceptHandler(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}

		_, _ = io.Copy(io.Discard, conn)
		if tcpc, ok := conn.(*net.TCPConn); ok {
			_ = tcpc.SetLinger(0)
		}
		conn.Close()
	}
}

// TcpGetInfo obtains information from a TCP socket via GETSOCKOPT(2) system call.
// The motivation for using this is twofold: 1) it is a way of triggering the kprobe
// responsible for the V4 offset guessing in kernel-space and 2) using it we can obtain
// in user-space TCP socket information such as RTT and use it for setting the expected
// values in the `fieldValues` struct.
func TcpGetInfo(conn net.Conn) (*unix.TCPInfo, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCPConn")
	}

	sysc, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error getting syscall connection: %w", err)
	}

	var tcpInfo *unix.TCPInfo
	ctrlErr := sysc.Control(func(fd uintptr) {
		tcpInfo, err = unix.GetsockoptTCPInfo(int(fd), syscall.SOL_TCP, syscall.TCP_INFO)
	})
	if err != nil {
		return nil, fmt.Errorf("error calling syscall.SYS_GETSOCKOPT: %w", err)
	}
	if ctrlErr != nil {
		return nil, fmt.Errorf("error controlling TCP connection: %w", ctrlErr)
	}
	return tcpInfo, nil
}

func (t *tracerOffsetGuesser) logAndAdvance(offset uint64, next GuessWhat) {
	guess := GuessWhat(t.status.What)
	if offset != notApplicable {
		log.Debugf("Successfully guessed %v with offset of %d bytes", whatString[guess], offset)
	} else {
		log.Debugf("Could not guess offset for %v", whatString[guess])
	}
	if next != GuessNotApplicable {
		log.Debugf("Started offset guessing for %v", whatString[next])
		t.status.What = uint64(next)
	}
}

func newUDPServer(addr string) (string, func(), error) {
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		b := make([]byte, 10)
		for {
			_ = ln.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _, err := ln.ReadFrom(b)
			if err != nil && !os.IsTimeout(err) {
				return
			}
		}
	}()

	doneFn := func() {
		_ = ln.Close()
		<-done
	}
	return ln.LocalAddr().String(), doneFn, nil
}

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
		var foundTcp, foundUdp bool
		for o := range offsets {
			switch offsets[o].Name {
			case "tcpv6_enabled":
				offsets[o] = boolConst("tcpv6_enabled", c.CollectTCPv6Conns)
				foundTcp = true
			case "udpv6_enabled":
				offsets[o] = boolConst("udpv6_enabled", c.CollectUDPv6Conns)
				foundUdp = true
			}
			if foundTcp && foundUdp {
				break
			}
		}
		if !foundTcp {
			offsets = append(offsets, boolConst("tcpv6_enabled", c.CollectTCPv6Conns))
		}
		if !foundUdp {
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
