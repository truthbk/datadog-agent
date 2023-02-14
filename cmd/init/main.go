// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

	if os.Getpid() == 1 {
		err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "power off failed: %v\n", err)
		}
	}
}

func run() error {
	if os.Getpid() == 1 {
		if err := os.Mkdir("/proc", 0755); err != nil {
			return fmt.Errorf("mkdir: %s", err)
		}
		if err := os.Mkdir("/sys", 0755); err != nil {
			return fmt.Errorf("mkdir: %s", err)
		}
		if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
			return fmt.Errorf("mount: %s", err)
		}
		if err := syscall.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
			return fmt.Errorf("mount: %s", err)
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rootns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get root netns: %s", err)
	}

	nsname := "bisectnetns"
	ns, err := netns.NewNamed(nsname)
	if err != nil {
		return fmt.Errorf("new netns: %s", err)
	}
	defer netns.DeleteNamed(nsname)
	defer ns.Close()

	// reset back to root netns
	if err := netns.Set(rootns); err != nil {
		return fmt.Errorf("set root netns: %s", err)
	}

	vethcloser, err := vethSetup(ns)
	if err != nil {
		return fmt.Errorf("veth: %s", err)
	}
	defer vethcloser()

	rootcloser, err := rootNftables()
	if err != nil {
		return fmt.Errorf("root nft: %s", err)
	}
	defer rootcloser()

	nscloser, err := nsNftables(int(ns))
	if err != nil {
		return fmt.Errorf("test nft: %s", err)
	}
	defer nscloser()

	// TCP server
	l, err := setupServer(ns)
	if err != nil {
		return fmt.Errorf("server: %s", err)
	}
	defer l.Close()

	// netlink listener

	// Open a Conntrack connection.
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Make a buffered channel to receive event updates on.
	evCh := make(chan conntrack.Event, 1024)

	// Listen for all Conntrack and Conntrack-Expect events with 4 decoder goroutines.
	// All errors caught in the decoders are passed on channel errCh.
	errCh, err := c.Listen(evCh, 4, netfilter.GroupsCT)
	if err != nil {
		log.Fatal(err)
	}

	// Listen to Conntrack events from all network namespaces on the system.
	err = c.SetOption(mdnetlink.ListenAllNSID, true)
	if err != nil {
		log.Fatal(err)
	}

	// TCP client
	conn, err := net.DialTimeout("tcp", "2.2.2.4:80", time.Second)
	if err != nil {
		return fmt.Errorf("dial: %s", err)
	}

	// Start a goroutine to print all incoming messages on the event channel.
	_, listenPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	listenPort, _ := strconv.Atoi(listenPortStr)
	srcIP := net.IPv4(2, 2, 2, 3)
	dstIP := net.IPv4(2, 2, 2, 4)
	//fmt.Printf("%s:%d <-> %s:%d\n", srcIP, listenPort, dstIP, 8080)
	donech := make(chan struct{})
	found := false
	go func() {
		defer close(donech)
		for {
			select {
			case ev := <-evCh:
				if (ev.Flow.TupleOrig.Proto.Protocol == syscall.IPPROTO_TCP &&
					ev.Flow.TupleOrig.IP.SourceAddress.Equal(srcIP) &&
					ev.Flow.TupleOrig.Proto.SourcePort == uint16(listenPort) &&
					ev.Flow.TupleOrig.IP.DestinationAddress.Equal(dstIP) &&
					ev.Flow.TupleOrig.Proto.DestinationPort == 80) &&
					(ev.Flow.TupleReply.Proto.Protocol == syscall.IPPROTO_TCP &&
						ev.Flow.TupleReply.IP.SourceAddress.Equal(dstIP) &&
						ev.Flow.TupleReply.Proto.SourcePort == 8080 &&
						ev.Flow.TupleReply.IP.DestinationAddress.Equal(srcIP) &&
						ev.Flow.TupleReply.Proto.DestinationPort == uint16(listenPort)) {
					found = true
					return
				} else {
					//fmt.Printf("[NO] %s %s %s\n", ev.Type, ev.Flow.TupleOrig, ev.Flow.TupleReply)
				}
			}
		}
	}()

	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return fmt.Errorf("write: %s", err)
	}
	bs := make([]byte, 10)
	_, err = conn.Read(bs)
	if err != nil {
		return fmt.Errorf("read: %s", err)
	}
	defer conn.Close()

	// wait for stop condition
	select {
	// Stop the program as soon as an error is caught in a decoder goroutine.
	case err = <-errCh:
		return fmt.Errorf("conntrack err: %s", err)
	case <-donech:
		if found {
			fmt.Println("===SUCCESS")
			return nil
		}
		return fmt.Errorf("connection not found")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timed out waiting for event")
	}

	return nil
}

func setupServer(ns netns.NsHandle) (net.Listener, error) {
	prevNS, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer prevNS.Close()

	if err := netns.Set(ns); err != nil {
		return nil, err
	}
	defer netns.Set(prevNS)

	l, err := net.Listen("tcp", "2.2.2.4:8080")
	if err != nil {
		return nil, err
	}

	ch := make(chan struct{})
	go func() {
		close(ch)
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}

			_, _ = conn.Write([]byte("hello"))
			conn.Close()
		}
	}()
	<-ch

	return l, nil
}

func vethSetup(ns netns.NsHandle) (func(), error) {
	// ip link add veth1 type peer name veth2
	v1 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "veth1",
		},
		PeerName: "veth2",
	}
	if err := netlink.LinkAdd(v1); err != nil {
		return nil, fmt.Errorf("ip link add: %s", err)
	}

	// ip link set veth2 netns %s
	v2, err := netlink.LinkByName("veth2")
	if err != nil {
		return nil, fmt.Errorf("veth2 find: %s", err)
	}
	if err := netlink.LinkSetNsFd(v2, int(ns)); err != nil {
		return nil, fmt.Errorf("ip link set veth2 netns: %s", err)
	}

	// ip address add 2.2.2.3/24 dev veth1
	v1addr, err := netlink.ParseAddr("2.2.2.3/24")
	if err != nil {
		return nil, fmt.Errorf("netlink parse 2.2.2.3/24 addr: %s", err)
	}
	if err := netlink.AddrAdd(v1, v1addr); err != nil {
		return nil, fmt.Errorf("ip addr add 2.2.2.3/24 dev veth1: %s", err)
	}

	// ip -n %s address add 2.2.2.4/24 dev veth2
	nsh, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %s", err)
	}
	defer nsh.Delete()

	v2addr, err := netlink.ParseAddr("2.2.2.4/24")
	if err != nil {
		return nil, fmt.Errorf("netlink parse 2.2.2.4/24 addr: %s", err)
	}
	if err := nsh.AddrAdd(v2, v2addr); err != nil {
		return nil, fmt.Errorf("ip -n <netns> addr add 2.2.2.4/24 dev veth2: %s", err)
	}

	// ip link set veth1 up
	if err := netlink.LinkSetUp(v1); err != nil {
		return nil, fmt.Errorf("ip link set veth1 up: %s", err)
	}

	// ip -n %s link set veth2 up
	if err := nsh.LinkSetUp(v2); err != nil {
		return nil, fmt.Errorf("ip -n <netns> link set veth2 up: %s", err)
	}

	// ip netns exec %s ip route add default via 2.2.2.3
	via := net.IPv4(2, 2, 2, 3)
	route := &netlink.Route{
		Dst: nil,
		Gw:  via,
	}
	if err := nsh.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("ip netns exec <netns> ip route add default via 2.2.2.3: %s", err)
	}
	return func() {
		netlink.LinkDel(v1)
	}, nil
}

func rootNftables() (func(), error) {
	rootnft, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("root netns new nft: %s", err)
	}

	filter := rootnft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	input := rootnft.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// iptables -I INPUT 1 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
	r1 := rootnft.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED | expr.CtStateBitNEW),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if err := rootnft.Flush(); err != nil {
		_ = rootnft.CloseLasting()
		return nil, fmt.Errorf("root iptables flush: %s", err)
	}

	return func() {
		_ = rootnft.DelRule(r1)
		_ = rootnft.Flush()
		_ = rootnft.CloseLasting()
	}, nil
}

func nsNftables(fd int) (func(), error) {
	nsnft, err := nftables.New(nftables.WithNetNSFd(fd), nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("test netns new nft: %s", err)
	}

	nsfilter := nsnft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	nspre := nsnft.AddChain(&nftables.Chain{
		Name:     "PREROUTING",
		Table:    nsfilter,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	// iptables -A PREROUTING -t nat -p tcp --dport 80 -j REDIRECT --to-port 8080
	r2 := nsnft.AddRule(&nftables.Rule{
		Table: nsfilter,
		Chain: nspre,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp eq reg 1 0x00001600 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x00, 0x50}, // port 80
			},
			&expr.Counter{},
			// [ immediate reg 1 0x0000ae08 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(8080),
			},
			// [ redir proto_min reg 1 ]
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	})

	// iptables -A PREROUTING -t nat -p udp --dport 80 -j REDIRECT --to-port 8080
	r3 := nsnft.AddRule(&nftables.Rule{
		Table: nsfilter,
		Chain: nspre,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp eq reg 1 0x00001600 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x00, 0x50}, // port 80
			},
			&expr.Counter{},
			// [ immediate reg 1 0x0000ae08 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(8080),
			},
			// [ redir proto_min reg 1 ]
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	})

	if err := nsnft.Flush(); err != nil {
		_ = nsnft.CloseLasting()
		return nil, fmt.Errorf("test netns iptables flush: %s", err)
	}

	return func() {
		_ = nsnft.DelRule(r3)
		_ = nsnft.DelRule(r2)
		_ = nsnft.Flush()
		_ = nsnft.CloseLasting()
	}, nil
}
