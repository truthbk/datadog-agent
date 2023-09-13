// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package offsetguess

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const InterfaceLocalMulticastIPv6 = "ff01::1"

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
