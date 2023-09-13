// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package offsetguess

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/util/native"
)

const listenIPv4 = "127.0.0.2"

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

func htons(a uint16) uint16 {
	var arr [2]byte
	binary.BigEndian.PutUint16(arr[:], a)
	return native.Endian.Uint16(arr[:])
}

func compareIPv6(a [4]uint32, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
