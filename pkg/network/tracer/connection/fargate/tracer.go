// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package fargate

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type fargateTracer struct {
	objs       fargateEBPFObjects
	recvLnk    link.Link
	queueLnk   link.Link
	retransLnk link.Link
	inetLnk    link.Link

	rd          *ringbuf.Reader
	removeTuple *Tuple
}

type fargateEBPFObjects struct {
	Conns       *ebpf.Map `ebpf:"conn_stats"`
	TCPStats    *ebpf.Map `ebpf:"tcp_stats"`
	ClosedConns *ebpf.Map `ebpf:"closed_conns"`

	NetifReceiveSKB  *ebpf.Program `ebpf:"trace_netif_receive_skb"`
	NetDevQueue      *ebpf.Program `ebpf:"trace_net_dev_queue"`
	TCPRetransmitSKB *ebpf.Program `ebpf:"trace_tcp_retransmit_skb"`
	InetSockSetState *ebpf.Program `ebpf:"trace_inet_sock_set_state"`
}

func New(cfg *config.Config) (connection.Tracer, error) {
	buf, err := netebpf.ReadBPFModule(cfg.BPFDir, "fargate-tracer", cfg.BPFDebug)
	if err != nil {
		return nil, fmt.Errorf("could not read bpf module: %s", err)
	}
	defer buf.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(buf)
	if err != nil {
		return nil, fmt.Errorf("unable to load collection spec: %w", err)
	}

	tr := fargateTracer{
		removeTuple: &Tuple{},
	}
	err = spec.LoadAndAssign(&tr.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSize:  1073741823,
		},
	})
	if err != nil {
		err = errors.Unwrap(errors.Unwrap(errors.Unwrap(err)))
		return nil, fmt.Errorf("unable to load and assign: %+v", err)
	}

	return &tr, nil
}

func (t *fargateTracer) Start(callback func([]network.ConnectionStats)) (err error) {
	defer func() {
		if err != nil {
			t.Stop()
		}
	}()

	t.recvLnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "netif_receive_skb",
		Program: t.objs.NetifReceiveSKB,
	})
	if err != nil {
		return fmt.Errorf("unable to attach raw tracepoint to netif_receive_skb: %s", err)
	}

	t.queueLnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "net_dev_queue",
		Program: t.objs.NetDevQueue,
	})
	if err != nil {
		return fmt.Errorf("unable to attach raw tracepoint to net_dev_queue: %s", err)
	}

	t.retransLnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_retransmit_skb",
		Program: t.objs.TCPRetransmitSKB,
	})
	if err != nil {
		return fmt.Errorf("unable to attach raw tracepoint to tcp_retransmit_skb: %s", err)
	}

	t.inetLnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "inet_sock_set_state",
		Program: t.objs.InetSockSetState,
	})
	if err != nil {
		return fmt.Errorf("unable to attach raw tracepoint to inet_sock_set_state: %s", err)
	}

	t.rd, err = ringbuf.NewReader(t.objs.ClosedConns)
	if err != nil {
		t.Stop()
		return fmt.Errorf("error creating closed_conns ringbuf: %s", err)
	}

	go func() {
		for {
			// TODO use ReadInto
			record, err := t.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			ce := (*ConnEvent)(unsafe.Pointer(&record.RawSample[0]))
			cs := network.ConnectionStats{}
			populateConnStats(&cs, &ce.Tup, &ce.Conn_stats)
			updateTCPStats(&cs, ce.Conn_stats.Cookie, &ce.Tcp_stats)
			log.Tracef("received %s", cs)
			callback([]network.ConnectionStats{cs})
		}
	}()

	return nil
}

func addrFromBytes(b [16]byte, family uint8) util.Address {
	switch family {
	case syscall.AF_INET:
		ip, _ := netip.AddrFromSlice(b[:4])
		return util.Address{Addr: ip}
	case syscall.AF_INET6:
		return util.Address{Addr: netip.AddrFrom16(b)}
	}
	return util.Address{}
}

func (t *fargateTracer) Stop() {
	if t.rd != nil {
		_ = t.rd.Close()
	}
	if t.recvLnk != nil {
		_ = t.recvLnk.Close()
	}
	if t.queueLnk != nil {
		_ = t.queueLnk.Close()
	}
	if t.retransLnk != nil {
		_ = t.retransLnk.Close()
	}
	if t.inetLnk != nil {
		_ = t.inetLnk.Close()
	}
	_ = t.objs.NetifReceiveSKB.Close()
	_ = t.objs.NetDevQueue.Close()
	_ = t.objs.TCPRetransmitSKB.Close()
	_ = t.objs.InetSockSetState.Close()
}

func (t *fargateTracer) GetConnections(buffer *network.ConnectionBuffer, filter func(*network.ConnectionStats) bool) error {
	// Iterate through all key-value pairs in map
	key, stats := &Tuple{}, &ConnStats{}
	seen := make(map[Tuple]struct{})

	// Cached objects
	conn := new(network.ConnectionStats)
	tcp := new(TCPStats)

	//tel := newTelemetry()
	entries := t.objs.Conns.Iterate()
	for entries.Next(unsafe.Pointer(key), unsafe.Pointer(stats)) {
		populateConnStats(conn, key, stats)

		//tel.addConnection(conn)

		if filter != nil && !filter(conn) {
			log.Tracef("skipping: %s", conn)
			continue
		}
		if t.getTCPStats(tcp, key, seen) {
			updateTCPStats(conn, stats.Cookie, tcp)
		}
		*buffer.Next() = *conn
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("unable to iterate connection map: %s", err)
	}

	//t.telemetry.assign(tel)

	return nil
}

func (t *fargateTracer) FlushPending() {
	//t.closeConsumer.FlushPending()
}

func (t *fargateTracer) Remove(conn *network.ConnectionStats) error {
	t.removeTuple.Sport = conn.SPort
	t.removeTuple.Dport = conn.DPort
	//t.removeTuple.Netns = conn.NetNS
	//t.removeTuple.Pid = conn.Pid
	//t.removeTuple.Saddr_l, t.removeTuple.Saddr_h = util.ToLowHigh(conn.Source)
	//t.removeTuple.Daddr_l, t.removeTuple.Daddr_h = util.ToLowHigh(conn.Dest)
	t.removeTuple.Saddr = conn.Source.As16()
	t.removeTuple.Daddr = conn.Dest.As16()

	if conn.Family == network.AFINET6 {
		t.removeTuple.Family = uint8(netebpf.IPv6)
	} else {
		t.removeTuple.Family = uint8(netebpf.IPv4)
	}
	if conn.Type == network.TCP {
		t.removeTuple.Protocol = uint8(netebpf.TCP)
	} else {
		t.removeTuple.Protocol = uint8(netebpf.UDP)
	}

	err := t.objs.Conns.Delete(unsafe.Pointer(t.removeTuple))
	if err != nil {
		// If this entry no longer exists in the eBPF map it means `tcp_close` has executed
		// during this function call. In that case state.StoreClosedConnection() was already called for this connection,
		// and we can't delete the corresponding client state, or we'll likely over-report the metric values.
		// By skipping to the next iteration and not calling state.RemoveConnections() we'll let
		// this connection expire "naturally" when either next connection check runs or the client itself expires.
		return err
	}

	//t.telemetry.removeConnection(conn)

	// We have to remove the PID to remove the element from the TCP Map since we don't use the pid there
	//t.removeTuple.Pid = 0
	// We can ignore the error for this map since it will not always contain the entry
	_ = t.objs.TCPStats.Delete(unsafe.Pointer(t.removeTuple))

	return nil
}

func (t *fargateTracer) GetTelemetry() map[string]int64 {
	return nil
}

func (t *fargateTracer) GetMap(s string) *ebpf.Map {
	return nil
}

func (t *fargateTracer) DumpMaps(maps ...string) (string, error) {
	//return t.m.DumpMaps(maps...)
	return "", nil
}

// getTCPStats reads tcp related stats for the given ConnTuple
func (t *fargateTracer) getTCPStats(stats *TCPStats, tuple *Tuple, seen map[Tuple]struct{}) bool {
	if tuple.Protocol != syscall.IPPROTO_TCP {
		return false
	}

	// The PID isn't used as a key in the stats map, we will temporarily set it to 0 here and reset it when we're done
	//pid := tuple.Pid
	//tuple.Pid = 0

	*stats = TCPStats{}
	err := t.objs.TCPStats.Lookup(unsafe.Pointer(tuple), unsafe.Pointer(stats))
	if err == nil {
		// This is required to avoid (over)reporting retransmits for connections sharing the same socket.
		//if _, reported := seen[*tuple]; reported {
		//	//t.pidCollisions.Inc()
		//	stats.Retransmits = 0
		//	stats.State_transitions = 0
		//} else {
		//	seen[*tuple] = struct{}{}
		//}
	}

	//tuple.Pid = pid
	return true
}

func updateTCPStats(conn *network.ConnectionStats, cookie uint32, tcpStats *TCPStats) {
	if conn.Type != network.TCP {
		return
	}

	m, _ := conn.Monotonic.Get(cookie)
	m.Retransmits = tcpStats.Retransmits
	m.TCPEstablished = uint32(tcpStats.State_transitions >> netebpf.Established & 1)
	m.TCPClosed = uint32(tcpStats.State_transitions >> netebpf.Close & 1)
	conn.Monotonic.Put(cookie, m)
	conn.RTT = tcpStats.Rtt
	conn.RTTVar = tcpStats.Rtt_var
}

func populateConnStats(stats *network.ConnectionStats, t *Tuple, s *ConnStats) {
	*stats = network.ConnectionStats{
		Source: addrFromBytes(t.Saddr, t.Family),
		SPort:  t.Sport,
		Dest:   addrFromBytes(t.Daddr, t.Family),
		DPort:  t.Dport,
		Family: network.FamilyFromSyscall(t.Family),
		Type:   network.ConnectionTypeFromSyscall(t.Protocol),
		Pid:    s.Pid,
		//NetNS:            t.Netns,
		SPortIsEphemeral: network.IsPortInEphemeralRange(t.Sport),
		LastUpdateEpoch:  s.Timestamp,
		//IsAssured:        s.IsAssured(),
	}

	stats.Monotonic.Put(s.Cookie, network.StatCounters{
		SentBytes:   s.Sent_bytes,
		RecvBytes:   s.Recv_bytes,
		SentPackets: s.Sent_packets,
		RecvPackets: s.Recv_packets,
	})

	log.Tracef("%+v %+v", t, s)
	switch ConnDirection(s.Direction) {
	case Incoming:
		stats.Direction = network.INCOMING
	case Outgoing:
		stats.Direction = network.OUTGOING
	default:
		// TODO revisit NONE
		stats.Direction = network.NONE
	}
}
