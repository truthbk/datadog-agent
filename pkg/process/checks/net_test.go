// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	sysconfig "github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/network/dns"
	"github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/datadog-agent/pkg/process/config"
)

func makeConnection(pid int32) *model.Connection {
	return &model.Connection{
		Pid:   pid,
		Laddr: &model.Addr{},
		Raddr: &model.Addr{},
	}
}

func makeConnections(n int) []*model.Connection {
	conns := make([]*model.Connection, 0, n)
	for i := 1; i <= n; i++ {
		c := makeConnection(int32(i))
		c.Laddr = &model.Addr{ContainerId: fmt.Sprintf("%d", c.Pid)}
		c.RouteIdx = int32(-1)

		conns = append(conns, c)
	}
	return conns
}

func TestDNSNameEncoding(t *testing.T) {
	p := makeConnections(5)
	p[0].Raddr.Ip = "1.1.2.1"
	p[1].Raddr.Ip = "1.1.2.2"
	p[2].Raddr.Ip = "1.1.2.3"
	p[3].Raddr.Ip = "1.1.2.4"
	p[4].Raddr.Ip = "1.1.2.5"

	dnsEntries := map[string]*model.DNSEntry{
		"1.1.2.1": {Names: []string{"host1.domain.com"}},
		"1.1.2.2": {Names: []string{"host2.domain.com", "host2.domain2.com"}},
		"1.1.2.3": {Names: []string{"host3.domain.com", "host3.domain2.com", "host3.domain3.com"}},
		"1.1.2.4": {Names: []string{"host4.domain.com"}},
		"1.1.2.5": {Names: nil},
	}
	cxs := &model.Connections{
		Conns: p,
		Dns:   dnsEntries,
	}
	cfg := config.NewDefaultAgentConfig()
	chunks := batchConnections(cfg, 0, cxs, "nid")
	assert.Equal(t, len(chunks), 1)

	chunk := chunks[0]
	conns := chunk.(*model.CollectorConnections)
	dnsParsed := make(map[string]*model.DNSEntry)
	for _, conn := range p {
		ip := conn.Raddr.Ip
		dnsParsed[ip] = &model.DNSEntry{}
		err := model.IterateDNSV2(conns.EncodedDnsLookups, ip,
			func(i, total int, entry int32) bool {
				host, e := conns.GetDNSNameByOffset(entry)
				assert.Nil(t, e)
				assert.Equal(t, total, len(dnsEntries[ip].Names))
				dnsParsed[ip].Names = append(dnsParsed[ip].Names, host)
				return true
			})
		require.NoError(t, err)
	}
	assert.Equal(t, dnsEntries, dnsParsed)

}

func TestNetworkConnectionBatching(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	for i, tc := range []struct {
		cur, last      []*model.Connection
		maxSize        int
		expectedTotal  int
		expectedChunks int
	}{
		{
			cur:            makeConnections(3),
			maxSize:        1,
			expectedTotal:  3,
			expectedChunks: 3,
		},
		{
			cur:            makeConnections(3),
			maxSize:        2,
			expectedTotal:  3,
			expectedChunks: 2,
		},
		{
			cur:            makeConnections(4),
			maxSize:        10,
			expectedTotal:  4,
			expectedChunks: 1,
		},
		{
			cur:            makeConnections(4),
			maxSize:        3,
			expectedTotal:  4,
			expectedChunks: 2,
		},
		{
			cur:            makeConnections(6),
			maxSize:        2,
			expectedTotal:  6,
			expectedChunks: 3,
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			cfg.MaxConnsPerMessage = tc.maxSize
			cxs := &model.Connections{
				Conns:                       tc.cur,
				Dns:                         map[string]*model.DNSEntry{},
				ConnTelemetryMap:            map[string]int64{},
				CompilationTelemetryByAsset: map[string]*model.RuntimeCompilationTelemetry{},
			}
			chunks := batchConnections(cfg, 0, cxs, "nid")

			assert.Len(t, chunks, tc.expectedChunks, "len %d", i)
			total := 0
			for i, c := range chunks {
				idx := i
				connections := c.(*model.CollectorConnections)
				total += len(connections.Connections)
				assert.Equal(t, int32(tc.expectedChunks), connections.GroupSize, "group size test %d", i)

				// make sure we could get container and pid mapping for connections
				assert.Equal(t, len(connections.Connections), len(connections.ContainerForPid))
				assert.Equal(t, "nid", connections.NetworkId)
				for _, conn := range connections.Connections {
					assert.Contains(t, connections.ContainerForPid, conn.Pid)
					assert.Equal(t, fmt.Sprintf("%d", conn.Pid), connections.ContainerForPid[conn.Pid])
				}

				// ensure only first chunk has telemetry
				if i == 0 {
					assert.NotNil(t, connections.ConnTelemetryMap, "chunk %d", idx)
					assert.NotNil(t, connections.CompilationTelemetryByAsset, "chunk %d", idx)
				} else {
					assert.Nil(t, connections.ConnTelemetryMap, "chunk %d", idx)
					assert.Nil(t, connections.CompilationTelemetryByAsset, "chunk %d", idx)
				}
			}
			assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
		})
	}
}

func TestNetworkConnectionBatchingWithDNS(t *testing.T) {
	p := makeConnections(4)
	p[3].Raddr.Ip = "1.1.2.3"

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 1

	cxs := &model.Connections{
		Conns: p,
		Dns: map[string]*model.DNSEntry{
			"1.1.2.3": {Names: []string{"datacat.edu"}},
		},
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 4)
	total := 0
	for i, c := range chunks {
		connections := c.(*model.CollectorConnections)

		// Only the last chunk should have a DNS mapping
		if i == 3 {
			assert.NotEmpty(t, connections.EncodedDnsLookups)
		} else {
			assert.Empty(t, connections.EncodedDnsLookups)
		}

		total += len(connections.Connections)
		assert.Equal(t, int32(4), connections.GroupSize)

		// make sure we could get container and pid mapping for connections
		assert.Equal(t, len(connections.Connections), len(connections.ContainerForPid))
		assert.Equal(t, "nid", connections.NetworkId)
		for _, conn := range connections.Connections {
			assert.Contains(t, connections.ContainerForPid, conn.Pid)
			assert.Equal(t, fmt.Sprintf("%d", conn.Pid), connections.ContainerForPid[conn.Pid])
		}
	}
	assert.Equal(t, 4, total)
}

func TestBatchSimilarConnectionsTogether(t *testing.T) {
	p := makeConnections(6)

	p[0].Raddr.Ip = "1.1.2.3"
	p[1].Raddr.Ip = "1.2.3.4"
	p[2].Raddr.Ip = "1.3.4.5"
	p[3].Raddr.Ip = "1.1.2.3"
	p[4].Raddr.Ip = "1.2.3.4"
	p[5].Raddr.Ip = "1.3.4.5"

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 2

	cxs := &model.Connections{
		Conns: p,
		Dns:   map[string]*model.DNSEntry{},
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 3)
	total := 0
	for _, c := range chunks {
		connections := c.(*model.CollectorConnections)
		total += len(connections.Connections)
		assert.Equal(t, int32(3), connections.GroupSize)
		assert.Equal(t, 2, len(connections.Connections))

		// make sure the connections with similar remote addresses were grouped together
		rAddr := connections.Connections[0].Raddr.Ip
		for _, cc := range connections.Connections {
			assert.Equal(t, rAddr, cc.Raddr.Ip)
		}

		// make sure the connections with the same remote address are ordered by PID
		lastSeenPID := connections.Connections[0].Pid
		for _, cc := range connections.Connections {
			assert.LessOrEqual(t, lastSeenPID, cc.Pid)
			lastSeenPID = cc.Pid
		}
	}
	assert.Equal(t, 6, total)
}

func indexOf(s string, db []string) int32 {
	for idx, val := range db {
		if val == s {
			return int32(idx)
		}
	}
	return -1
}

func TestNetworkConnectionBatchingWithDomainsByQueryType(t *testing.T) {
	conns := makeConnections(4)

	domains := []string{"foo.com", "bar.com", "baz.com"}
	conns[1].DnsStatsByDomainByQueryType = map[int32]*model.DNSStatsByQueryType{
		0: {
			DnsStatsByQueryType: map[int32]*model.DNSStats{
				int32(dns.TypeA): {
					DnsTimeouts: 1,
				},
			},
		},
	}
	conns[2].DnsStatsByDomainByQueryType = map[int32]*model.DNSStatsByQueryType{
		0: {
			DnsStatsByQueryType: map[int32]*model.DNSStats{
				int32(dns.TypeA): {
					DnsTimeouts: 2,
				},
			},
		},
		2: {
			DnsStatsByQueryType: map[int32]*model.DNSStats{
				int32(dns.TypeA): {
					DnsTimeouts: 3,
				},
			},
		},
	}
	conns[3].DnsStatsByDomainByQueryType = map[int32]*model.DNSStatsByQueryType{
		1: {
			DnsStatsByQueryType: map[int32]*model.DNSStats{
				int32(dns.TypeA): {
					DnsTimeouts: 4,
				},
			},
		},
		2: {
			DnsStatsByQueryType: map[int32]*model.DNSStats{
				int32(dns.TypeA): {
					DnsTimeouts: 5,
				},
			},
		},
	}
	dnsmap := map[string]*model.DNSEntry{}

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 1

	cxs := &model.Connections{
		Conns:   conns,
		Dns:     dnsmap,
		Domains: domains,
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 4)
	total := 0
	for i, c := range chunks {
		connections := c.(*model.CollectorConnections)
		total += len(connections.Connections)

		domaindb, _ := connections.GetDNSNames()

		// verify nothing was put in the DnsStatsByDomain bucket by mistake
		assert.Equal(t, len(connections.Connections[0].DnsStatsByDomain), 0)
		assert.Equal(t, len(connections.Connections[0].DnsStatsByDomainByQueryType), 0)

		switch i {
		case 0:
			assert.Equal(t, len(domaindb), 0)
		case 1:
			assert.Equal(t, len(domaindb), 1)
			assert.Equal(t, domains[0], domaindb[0])

			// check for correctness of the data
			conn := connections.Connections[0]
			//val, ok := conn.DnsStatsByDomainByQueryType[0]
			assert.Equal(t, 1, len(conn.DnsStatsByDomainOffsetByQueryType))
			// we don't know what hte offset will be, but since there's only one
			// the iteration should only happen once
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)
				assert.Equal(t, domainstr, domains[0])
				assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(1))
			}

		case 2:
			assert.Equal(t, len(domaindb), 2)
			assert.Contains(t, domaindb, domains[0])
			assert.Contains(t, domaindb, domains[2])
			assert.NotContains(t, domaindb, domains[1])

			conn := connections.Connections[0]
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)

				idx := indexOf(domainstr, domains)
				assert.NotEqual(t, -1, idx)

				switch idx {
				case 0:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(2))
				case 2:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(3))
				default:
					assert.True(t, false, fmt.Sprintf("unexpected index %v", idx))
				}
			}

		case 3:
			assert.Equal(t, len(domaindb), 2)
			assert.Contains(t, domaindb, domains[1])
			assert.Contains(t, domaindb, domains[2])
			assert.NotContains(t, domaindb, domains[0])

			conn := connections.Connections[0]
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)

				idx := indexOf(domainstr, domains)
				assert.NotEqual(t, -1, idx)

				switch idx {
				case 1:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(4))
				case 2:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(5))
				default:
					assert.True(t, false, fmt.Sprintf("unexpected index %v", idx))
				}
			}
		}
	}
	assert.Equal(t, 4, total)
}

func TestNetworkConnectionBatchingWithDomains(t *testing.T) {
	conns := makeConnections(4)

	domains := []string{"foo.com", "bar.com", "baz.com"}
	conns[1].DnsStatsByDomain = map[int32]*model.DNSStats{
		0: {
			DnsTimeouts: 1,
		},
	}
	conns[2].DnsStatsByDomain = map[int32]*model.DNSStats{
		0: {
			DnsTimeouts: 2,
		},
		2: {
			DnsTimeouts: 3,
		},
	}
	conns[3].DnsStatsByDomain = map[int32]*model.DNSStats{
		1: {
			DnsTimeouts: 4,
		},
		2: {
			DnsTimeouts: 5,
		},
	}
	dnsmap := map[string]*model.DNSEntry{}

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 1

	cxs := &model.Connections{
		Conns:   conns,
		Dns:     dnsmap,
		Domains: domains,
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 4)
	total := 0
	for i, c := range chunks {
		connections := c.(*model.CollectorConnections)
		total += len(connections.Connections)

		domaindb, _ := connections.GetDNSNames()

		// verify nothing was put in the DnsStatsByDomain bucket by mistake
		assert.Equal(t, len(connections.Connections[0].DnsStatsByDomain), 0)
		// verify nothing was put in the DnsStatsByDomainByQueryType bucket by mistake
		assert.Equal(t, len(connections.Connections[0].DnsStatsByDomainByQueryType), 0)

		switch i {
		case 0:
			assert.Equal(t, len(domaindb), 0)
		case 1:
			assert.Equal(t, len(domaindb), 1)
			assert.Equal(t, domains[0], domaindb[0])

			// check for correctness of the data
			conn := connections.Connections[0]
			// we don't know what hte offset will be, but since there's only one
			// the iteration should only happen once
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)
				assert.Equal(t, domainstr, domains[0])
				assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(1))
			}
		case 2:
			assert.Equal(t, len(domaindb), 2)
			assert.Contains(t, domaindb, domains[0])
			assert.Contains(t, domaindb, domains[2])
			assert.NotContains(t, domaindb, domains[1])

			conn := connections.Connections[0]
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)

				idx := indexOf(domainstr, domains)
				assert.NotEqual(t, -1, idx)

				switch idx {
				case 0:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(2))
				case 2:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(3))
				default:
					assert.True(t, false, fmt.Sprintf("unexpected index %v", idx))
				}
			}

		case 3:
			assert.Equal(t, len(domaindb), 2)
			assert.Contains(t, domaindb, domains[1])
			assert.Contains(t, domaindb, domains[2])
			assert.NotContains(t, domaindb, domains[0])

			conn := connections.Connections[0]
			for off, val := range conn.DnsStatsByDomainOffsetByQueryType {
				// first, verify the hostname is what we expect
				domainstr, err := connections.GetDNSNameByOffset(off)
				assert.Nil(t, err)

				idx := indexOf(domainstr, domains)
				assert.NotEqual(t, -1, idx)

				switch idx {
				case 1:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(4))
				case 2:
					assert.Equal(t, val.DnsStatsByQueryType[int32(dns.TypeA)].DnsTimeouts, uint32(5))
				default:
					assert.True(t, false, fmt.Sprintf("unexpected index %v", idx))
				}
			}
		}
	}
	assert.Equal(t, 4, total)
}

func TestNetworkConnectionBatchingWithRoutes(t *testing.T) {
	conns := makeConnections(8)

	routes := []*model.Route{
		{Subnet: &model.Subnet{Alias: "foo1"}},
		{Subnet: &model.Subnet{Alias: "foo2"}},
		{Subnet: &model.Subnet{Alias: "foo3"}},
		{Subnet: &model.Subnet{Alias: "foo4"}},
		{Subnet: &model.Subnet{Alias: "foo5"}},
	}

	conns[0].RouteIdx = 0
	conns[1].RouteIdx = 1
	conns[2].RouteIdx = 2
	conns[3].RouteIdx = 3
	conns[4].RouteIdx = -1
	conns[5].RouteIdx = 4
	conns[6].RouteIdx = 3
	conns[7].RouteIdx = 2

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 4

	cxs := &model.Connections{
		Conns:  conns,
		Routes: routes,
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 2)
	total := 0
	for i, c := range chunks {
		connections := c.(*model.CollectorConnections)
		total += len(connections.Connections)
		switch i {
		case 0:
			require.Equal(t, int32(0), connections.Connections[0].RouteIdx)
			require.Equal(t, int32(1), connections.Connections[1].RouteIdx)
			require.Equal(t, int32(2), connections.Connections[2].RouteIdx)
			require.Equal(t, int32(3), connections.Connections[3].RouteIdx)
			require.Len(t, connections.Routes, 4)
			require.Equal(t, routes[0].Subnet.Alias, connections.Routes[0].Subnet.Alias)
			require.Equal(t, routes[1].Subnet.Alias, connections.Routes[1].Subnet.Alias)
			require.Equal(t, routes[2].Subnet.Alias, connections.Routes[2].Subnet.Alias)
			require.Equal(t, routes[3].Subnet.Alias, connections.Routes[3].Subnet.Alias)
		case 1:
			require.Equal(t, int32(-1), connections.Connections[0].RouteIdx)
			require.Equal(t, int32(0), connections.Connections[1].RouteIdx)
			require.Equal(t, int32(1), connections.Connections[2].RouteIdx)
			require.Equal(t, int32(2), connections.Connections[3].RouteIdx)
			require.Len(t, connections.Routes, 3)
			require.Equal(t, routes[4].Subnet.Alias, connections.Routes[0].Subnet.Alias)
			require.Equal(t, routes[3].Subnet.Alias, connections.Routes[1].Subnet.Alias)
			require.Equal(t, routes[2].Subnet.Alias, connections.Routes[2].Subnet.Alias)
		}
	}
	assert.Equal(t, 8, total)
}

func TestNetworkConnectionTags(t *testing.T) {
	conns := makeConnections(8)

	tags := []string{
		"tag0",
		"tag1",
		"tag2",
		"tag3",
	}

	conns[0].Tags = []uint32{0}
	// conns[1] contains no tags
	conns[2].Tags = []uint32{0, 2}
	conns[3].Tags = []uint32{1, 2}
	conns[4].Tags = []uint32{1}
	conns[5].Tags = []uint32{2}
	conns[6].Tags = []uint32{3}
	conns[7].Tags = []uint32{2, 3}

	type fakeConn struct {
		tags []string
	}
	expectedTags := []fakeConn{
		{tags: []string{"tag0"}},
		{},
		{tags: []string{"tag0", "tag2"}},
		{tags: []string{"tag1", "tag2"}},
		{tags: []string{"tag1"}},
		{tags: []string{"tag2"}},
		{tags: []string{"tag3"}},
		{tags: []string{"tag2", "tag3"}},
	}
	var foundTags []fakeConn

	cfg := config.NewDefaultAgentConfig()
	cfg.MaxConnsPerMessage = 4

	cxs := &model.Connections{
		Conns: conns,
		Tags:  tags,
	}
	chunks := batchConnections(cfg, 0, cxs, "nid")

	assert.Len(t, chunks, 2)
	total := 0
	for _, c := range chunks {
		connections := c.(*model.CollectorConnections)
		total += len(connections.Connections)
		for _, conn := range connections.Connections {
			// conn.Tags must be used between system-probe and the agent only
			assert.Nil(t, conn.Tags)

			foundTags = append(foundTags, fakeConn{tags: connections.GetConnectionsTags(conn.TagsIdx)})
		}
	}

	assert.Equal(t, 8, total)
	require.EqualValues(t, expectedTags, foundTags)
}

func TestNetworkIntegration(t *testing.T) {
	skipUnless(t, "network-integration")
	require.Equal(t, 0, os.Getuid(), "you must run this test as root, since it starts system-probe")

	td := t.TempDir()
	scfgfile := filepath.Join(td, "system-probe.yaml")
	cfgContent := fmt.Sprintf(`
system_probe_config:
  sysprobe_socket: %s
network_config:
  enabled: true
`, filepath.Join(td, "sysprobe.sock"))
	err := ioutil.WriteFile(scfgfile, []byte(cfgContent), 0666)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	sp := exec.CommandContext(ctx, "../../../bin/system-probe/system-probe", "-c", scfgfile)
	sp.Env = []string{"DD_LOG_LEVEL=trace"}
	var out bytes.Buffer
	sp.Stdout = &out
	sp.Stderr = &out
	err = sp.Start()
	require.NoError(t, err, out.String())
	t.Cleanup(cancel)

	syscfg, err := sysconfig.New(scfgfile)
	require.NoError(t, err)

	// process_config.grpc_connection_timeout_secs
	t.Setenv("DD_PROCESS_CONFIG_GRPC_CONNECTION_TIMEOUT_SECS", "1")
	cfg, err := config.NewAgentConfig("PROCESS-TEST", "", syscfg)
	require.NoError(t, err)

	check := &ConnectionsCheck{
		lastConnsByPID: &atomic.Value{},
	}
	check.Init(cfg, nil)
	t.Cleanup(check.Cleanup)

	const ip = "127.0.0.2"
	const port = 12345
	const connCount = 100
	shutdown := testutil.StartServerTCP(t, net.ParseIP(ip), port)
	for i := 0; i < connCount; i++ {
		tcpConn := testutil.PingTCP(t, net.ParseIP(ip), port)
		tcpConn.Close()
	}
	shutdown.Close()

	time.Sleep(1 * time.Second)

	res, err := check.RunWithPooledData(cfg, 1)
	require.NoError(t, err)
	require.NotNil(t, res, out.String())
	require.NotNil(t, res.DoneFunc)
	t.Cleanup(res.DoneFunc)

	err = sp.Process.Signal(os.Interrupt)
	require.NoError(t, err)
	err = sp.Wait()
	require.NoError(t, err, out.String())

	require.Len(t, res.Data, int(groupSize(connCount*2, cfg.MaxConnsPerMessage)))
	cc, ok := res.Data[0].(*model.CollectorConnections)
	require.True(t, ok)
	// times 2 because we get client and server
	require.GreaterOrEqual(t, len(cc.Connections), connCount*2)

	// uncomment to see system-probe output
	//t.Log(out.String())
}

func skipUnless(t *testing.T, requiredArg string) {
	for _, arg := range os.Args[1:] {
		if arg == requiredArg {
			return
		}
	}

	t.Skip(
		fmt.Sprintf(
			"skipped %s. you can enable it by using running tests with `-args %s`.\n",
			t.Name(),
			requiredArg,
		),
	)
}
