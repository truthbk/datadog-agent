// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package encoding

import (
	"fmt"
	"sync"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/richardartoul/molecule"
	"github.com/richardartoul/molecule/src/codec"
	"golang.org/x/exp/maps"
)

var ccPool = sync.Pool{New: func() interface{} { return new(model.CollectorConnections) }}
var connsPool = sync.Pool{New: func() interface{} { return new(model.Connections) }}
var cPool = sync.Pool{New: func() interface{} { return new(model.Connection) }}
var rcTelemetryPool = sync.Pool{New: func() interface{} { return new(model.RuntimeCompilationTelemetry) }}
var agentConfigPool = sync.Pool{New: func() interface{} { return new(model.AgentConfiguration) }}
var routePool = sync.Pool{New: func() interface{} { return new(model.Route) }}
var subnetPool = sync.Pool{New: func() interface{} { return new(model.Subnet) }}
var dnsEntryPool = sync.Pool{New: func() interface{} { return new(model.DNSEntry) }}
var addrPool = sync.Pool{New: func() interface{} { return new(model.Addr) }}
var ipTranslationPool = sync.Pool{New: func() interface{} { return new(model.IPTranslation) }}
var dnsStatsPool = sync.Pool{New: func() interface{} { return new(model.DNSStats) }}
var dnsStatsQueryTypePool = sync.Pool{New: func() interface{} { return new(model.DNSStatsByQueryType) }}

type moleculeDecoder struct {
	connsBuffer          *codec.Buffer
	connBuffer           *codec.Buffer
	miscBuffer           *codec.Buffer
	rcTelemetryBuffer    *codec.Buffer
	routeBuffer          *codec.Buffer
	dnsEntryBuffer       *codec.Buffer
	dnsStatsBuffer       *codec.Buffer
	dnsRcodeBuffer       *codec.Buffer
	dnsStatsDomainBuffer *codec.Buffer
}

// GetCollectorConnections returns a *model.CollectorConnections from the pool
func GetCollectorConnections() *model.CollectorConnections {
	cc := ccPool.Get().(*model.CollectorConnections)
	if cc.ContainerForPid == nil {
		cc.ContainerForPid = make(map[int32]string)
	}
	return cc
}

// ResetDNS resets the DNS fields on a *model.Connection
func ResetDNS(c *model.Connection) {
	resetDNSStatsByDomain(c)
	resetDNSStatsByDomainByQueryType(c)
	resetDNSStatsByDomainOffsetByQueryType(c)
}

func resetDNSStats(s *model.DNSStats) {
	s.DnsTimeouts = 0
	s.DnsSuccessLatencySum = 0
	s.DnsFailureLatencySum = 0
	maps.Clear(s.DnsCountByRcode)
}

func resetDNSStatsByDomain(c *model.Connection) {
	for k, v := range c.DnsStatsByDomain {
		resetDNSStats(v)
		dnsStatsPool.Put(v)
		delete(c.DnsStatsByDomain, k)
	}
}

func resetDNSStatsByDomainByQueryType(c *model.Connection) {
	for k, v := range c.DnsStatsByDomainByQueryType {
		resetDNSStatsByQueryType(v)
		delete(c.DnsStatsByDomainByQueryType, k)
	}
}

func resetDNSStatsByQueryType(c *model.DNSStatsByQueryType) {
	for k, v := range c.DnsStatsByQueryType {
		resetDNSStats(v)
		dnsStatsPool.Put(v)
		delete(c.DnsStatsByQueryType, k)
	}
	dnsStatsQueryTypePool.Put(c)
}

func resetDNSStatsByDomainOffsetByQueryType(c *model.Connection) {
	for k, v := range c.DnsStatsByDomainOffsetByQueryType {
		resetDNSStatsByQueryType(v)
		delete(c.DnsStatsByDomainOffsetByQueryType, k)
	}
}

// PutCollectorConnections returns a *model.CollectorConnections to the pool
func PutCollectorConnections(cc *model.CollectorConnections) {
	resetCollectorConnections(cc)
	ccPool.Put(cc)
}

func resetCollectorConnections(cc *model.CollectorConnections) {
	cc.HostName = ""
	cc.NetworkId = ""
	cc.HostId = 0
	// owned by model.Connections.Conns
	cc.Connections = cc.Connections[:0]
	cc.GroupId = 0
	cc.GroupSize = 0
	maps.Clear(cc.ContainerForPid)
	cc.EncodedTags = cc.EncodedTags[:0]
	cc.EncodedConnectionsTags = cc.EncodedConnectionsTags[:0]
	cc.ContainerHostType = model.ContainerHostType_notSpecified
	// owned by model.Connections.ConnTelemetryMap
	cc.ConnTelemetryMap = nil
	cc.Architecture = ""
	cc.KernelVersion = ""
	cc.Platform = ""
	cc.PlatformVersion = ""
	// owned by model.Connections.CompilationTelemetryByAsset
	cc.CompilationTelemetryByAsset = nil
	// owned by model.Connections.Routes
	cc.Routes = cc.Routes[:0]
	// owned by model.Connections.AgentConfiguration
	cc.AgentConfiguration = nil
	cc.EncodedDNS = cc.EncodedDNS[:0]
	cc.Domains = cc.Domains[:0]
	// these will get overwritten, so no chance of reuse
	cc.EncodedDomainDatabase = nil
	cc.EncodedDnsLookups = nil
}

// ResetConnections restores itself and nested objects back to the sync pools.
func ResetConnections(conns *model.Connections) {
	for _, c := range conns.Conns {
		resetConnection(c)
		cPool.Put(c)
	}
	conns.Conns = conns.Conns[:0]

	for k, de := range conns.Dns {
		de.Names = de.Names[:0]
		// no .Reset() because it would set slice to nil and not reuse allocations
		dnsEntryPool.Put(de)
		delete(conns.Dns, k)
	}
	conns.Domains = conns.Domains[:0]
	for _, r := range conns.Routes {
		if r.Subnet != nil {
			r.Subnet.Reset()
			subnetPool.Put(r.Subnet)
			r.Subnet = nil
		}
		r.Reset()
		routePool.Put(r)
	}
	conns.Routes = conns.Routes[:0]
	for k, rc := range conns.CompilationTelemetryByAsset {
		rc.Reset()
		rcTelemetryPool.Put(rc)
		delete(conns.CompilationTelemetryByAsset, k)
	}
	if conns.AgentConfiguration != nil {
		conns.AgentConfiguration.Reset()
		agentConfigPool.Put(conns.AgentConfiguration)
		conns.AgentConfiguration = nil
	}
	conns.Tags = conns.Tags[:0]
	maps.Clear(conns.ConnTelemetryMap)
}

func resetConnection(c *model.Connection) {
	c.Pid = 0
	if c.Laddr != nil {
		c.Laddr.Reset()
		addrPool.Put(c.Laddr)
		c.Laddr = nil
	}
	if c.Raddr != nil {
		c.Raddr.Reset()
		addrPool.Put(c.Raddr)
		c.Raddr = nil
	}
	c.Family = model.ConnectionFamily(0)
	c.Type = model.ConnectionType(0)
	c.PidCreateTime = 0
	c.IsLocalPortEphemeral = model.EphemeralPortState(0)
	c.LastBytesSent = 0
	c.LastBytesReceived = 0
	c.LastRetransmits = 0
	c.Direction = model.ConnectionDirection(0)
	c.LastPacketsSent = 0
	c.LastPacketsReceived = 0
	c.NetNS = 0
	c.RemoteNetworkId = ""
	if c.IpTranslation != nil {
		c.IpTranslation.Reset()
		ipTranslationPool.Put(c.IpTranslation)
		c.IpTranslation = nil
	}
	c.Rtt = 0
	c.RttVar = 0
	c.IntraHost = false
	c.DnsSuccessfulResponses = 0
	c.DnsFailedResponses = 0
	c.DnsTimeouts = 0
	c.DnsSuccessLatencySum = 0
	c.DnsFailureLatencySum = 0
	maps.Clear(c.DnsCountByRcode)
	c.LastTcpEstablished = 0
	c.LastTcpClosed = 0

	ResetDNS(c)

	c.RouteIdx = 0
	c.RouteTargetIdx = 0
	c.HttpAggregations = c.HttpAggregations[:0]
	c.Tags = c.Tags[:0]
	c.TagsIdx = 0
	c.TagsChecksum = 0
}

func newMoleculeDecoder() *moleculeDecoder {
	return &moleculeDecoder{
		connsBuffer:          codec.NewBuffer(nil),
		connBuffer:           codec.NewBuffer(nil),
		miscBuffer:           codec.NewBuffer(nil),
		rcTelemetryBuffer:    codec.NewBuffer(nil),
		routeBuffer:          codec.NewBuffer(nil),
		dnsEntryBuffer:       codec.NewBuffer(nil),
		dnsStatsBuffer:       codec.NewBuffer(nil),
		dnsRcodeBuffer:       codec.NewBuffer(nil),
		dnsStatsDomainBuffer: codec.NewBuffer(nil),
	}
}

func (m *moleculeDecoder) Unmarshal(b []byte) (*model.Connections, error) {
	defer m.reset()
	conns := connsPool.Get().(*model.Connections)
	err := m.decodeConnections(b, conns)
	if err != nil {
		ResetConnections(conns)
		connsPool.Put(conns)
		return nil, err
	}
	return conns, nil
}

func (m *moleculeDecoder) reset() {
	m.connsBuffer.Reset(nil)
	m.connBuffer.Reset(nil)
	m.miscBuffer.Reset(nil)
	m.rcTelemetryBuffer.Reset(nil)
	m.routeBuffer.Reset(nil)
	m.dnsEntryBuffer.Reset(nil)
	m.dnsStatsBuffer.Reset(nil)
	m.dnsRcodeBuffer.Reset(nil)
	m.dnsStatsDomainBuffer.Reset(nil)
}

func (m *moleculeDecoder) decodeConnections(data []byte, conns *model.Connections) error {
	m.connsBuffer.Reset(data)

	return molecule.MessageEach(m.connsBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // Conns
			err = m.handleConns(conns, value)
		case 2: // Dns
			err = m.handleDNS(conns, value)
		case 3: // ConnTelemetry
			// deprecated
		case 4: // Domains
			conns.Domains, err = decodeStringSlice(conns.Domains, value)
		case 5: // Routes
			err = m.handleRoutes(conns, value)
		case 6: // CompilationTelemetryByAsset
			err = m.handleCompilationTelemetryByAsset(conns, value)
		case 7: // AgentConfiguration
			conns.AgentConfiguration, err = m.handleAgentConfiguration(value)
		case 8: // Tags
			conns.Tags, err = decodeStringSlice(conns.Tags, value)
		case 9: // ConnTelemetryMap
			err = m.handleConnTelemetryMap(conns, value)
		default:
			return false, fmt.Errorf("unknown Connections field number %d", fieldNum)
		}
		return err == nil, err
	})
}

func (m *moleculeDecoder) handleConns(conns *model.Connections, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.connBuffer.Reset(buf)

	conn := cPool.Get().(*model.Connection)

	err = molecule.MessageEach(m.connBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // Pid
			conn.Pid, err = value.AsInt32()
		case 5: // Laddr
			conn.Laddr, err = m.handleAddr(value)
		case 6: // Raddr
			conn.Raddr, err = m.handleAddr(value)
		case 10: // Family
			v, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			conn.Family = model.ConnectionFamily(v)
		case 11: // Type
			v, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			conn.Type = model.ConnectionType(v)
		case 12: // PidCreateTime
			conn.PidCreateTime, err = value.AsInt64()
		case 41: // IsLocalPortEphemeral
			v, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			conn.IsLocalPortEphemeral = model.EphemeralPortState(v)
		case 16: // LastBytesSent
			conn.LastBytesSent, err = value.AsUint64()
		case 17: // LastBytesReceived
			conn.LastBytesReceived, err = value.AsUint64()
		case 18: // LastRetransmits
			conn.LastRetransmits, err = value.AsUint32()
		case 19: // Direction
			v, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			conn.Direction = model.ConnectionDirection(v)
		case 38: // LastPacketsSent
			conn.LastPacketsSent, err = value.AsUint64()
		case 39: // LastPacketsReceived
			conn.LastPacketsReceived, err = value.AsUint64()
		case 20: // NetNS
			conn.NetNS, err = value.AsUint32()
		case 32: // RemoteNetworkId
			conn.RemoteNetworkId, err = value.AsStringUnsafe()
		case 21: // IPTranslation
			conn.IpTranslation, err = m.handleIPTranslation(value)
		case 22: // Rtt
			conn.Rtt, err = value.AsUint32()
		case 23: // RttVar
			conn.RttVar, err = value.AsUint32()
		case 24: // IntraHost
			conn.IntraHost, err = value.AsBool()
		case 25: // DnsSuccessfulResponses
			conn.DnsSuccessfulResponses, err = value.AsUint32()
		case 26: // DnsFailedResponses
			conn.DnsFailedResponses, err = value.AsUint32()
		case 27: // DnsTimeouts
			conn.DnsTimeouts, err = value.AsUint32()
		case 28: // DnsSuccessLatencySum
			conn.DnsSuccessLatencySum, err = value.AsUint64()
		case 29: // DnsFailureLatencySum
			conn.DnsFailureLatencySum, err = value.AsUint64()
		case 33: // DnsCountByRcode
			if conn.DnsCountByRcode == nil {
				conn.DnsCountByRcode = make(map[uint32]uint32)
			}
			err = m.handleDNSCountByRcode(conn.DnsCountByRcode, value)
		case 30: // LastTcpEstablished
			conn.LastTcpEstablished, err = value.AsUint32()
		case 31: // LastTcpClosed
			conn.LastTcpClosed, err = value.AsUint32()
		case 34: // DnsStatsByDomain
			if conn.DnsStatsByDomain == nil {
				conn.DnsStatsByDomain = make(map[int32]*model.DNSStats)
			}
			err = m.handleDNSStatsByDomain(conn.DnsStatsByDomain, value)
		case 42: // DnsStatsByDomainByQueryType
			if conn.DnsStatsByDomainByQueryType == nil {
				conn.DnsStatsByDomainByQueryType = make(map[int32]*model.DNSStatsByQueryType)
			}
			err = m.handleDNSStatsByDomainByQueryType(conn.DnsStatsByDomainByQueryType, value)
		case 43: // DnsStatsByDomainOffsetByQueryType
			if conn.DnsStatsByDomainOffsetByQueryType == nil {
				conn.DnsStatsByDomainOffsetByQueryType = make(map[int32]*model.DNSStatsByQueryType)
			}
			err = m.handleDNSStatsByDomainByQueryType(conn.DnsStatsByDomainOffsetByQueryType, value)
		case 36: // RouteIdx
			conn.RouteIdx, err = value.AsInt32()
		case 40: // RouteTargetIdx
			conn.RouteTargetIdx, err = value.AsInt32()
		case 37: // HttpAggregations
			conn.HttpAggregations, err = value.AsBytesUnsafe()
		case 44: // Tags
			tag, err := value.AsUint32()
			if err != nil {
				return false, err
			}
			conn.Tags = append(conn.Tags, tag)
		case 45: // TagsIdx
			conn.TagsIdx, err = value.AsInt32()
		case 47: // TagsChecksum
			conn.TagsChecksum, err = value.AsUint32()
		default:
			return false, fmt.Errorf("unknown Connection field number %d", fieldNum)
		}
		return err == nil, err
	})
	if err != nil {
		resetConnection(conn)
		cPool.Put(conn)
		return err
	}
	conns.Conns = append(conns.Conns, conn)
	return nil
}

// GetDNSStatsByQueryType returns a *model.DNSStatsByQueryType from the pool
func GetDNSStatsByQueryType() *model.DNSStatsByQueryType {
	return dnsStatsQueryTypePool.Get().(*model.DNSStatsByQueryType)
}

func (m *moleculeDecoder) handleDNSStatsByDomainByQueryType(dnsMap map[int32]*model.DNSStatsByQueryType, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.miscBuffer.Reset(buf)

	var key int32
	val := GetDNSStatsByQueryType()

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsInt32()
		case 2:
			err = m.handleDNSStatsByQueryType(val, value)
		}
		return err == nil, err
	})
	if err != nil {
		resetDNSStatsByQueryType(val)
		dnsStatsQueryTypePool.Put(val)
		return err
	}
	dnsMap[key] = val
	return nil
}

func (m *moleculeDecoder) handleDNSStatsByQueryType(stats *model.DNSStatsByQueryType, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.dnsStatsBuffer.Reset(buf)

	return molecule.MessageEach(m.dnsStatsBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			if stats.DnsStatsByQueryType == nil {
				stats.DnsStatsByQueryType = make(map[int32]*model.DNSStats)
			}
			err = m.handleDNSStatsByDomain(stats.DnsStatsByQueryType, value)
		default:
			return false, fmt.Errorf("unknown DNSStatsByQueryType field number %d", fieldNum)
		}
		return err == nil, err
	})
}

func (m *moleculeDecoder) handleDNSStatsByDomain(statsMap map[int32]*model.DNSStats, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.dnsStatsDomainBuffer.Reset(buf)

	var key int32
	val := dnsStatsPool.Get().(*model.DNSStats)

	err = molecule.MessageEach(m.dnsStatsDomainBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsInt32()
		case 2:
			err = m.handleDNSStats(val, value)
		}
		return err == nil, err
	})
	if err != nil {
		resetDNSStats(val)
		dnsStatsPool.Put(val)
		return err
	}
	statsMap[key] = val
	return nil
}

func (m *moleculeDecoder) handleDNSStats(stats *model.DNSStats, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.dnsStatsBuffer.Reset(buf)

	return molecule.MessageEach(m.dnsStatsBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // DnsTimeouts
			stats.DnsTimeouts, err = value.AsUint32()
		case 2: // DnsSuccessLatencySum
			stats.DnsSuccessLatencySum, err = value.AsUint64()
		case 3: // DnsFailureLatencySum
			stats.DnsFailureLatencySum, err = value.AsUint64()
		case 4: // DnsCountByRcode
			if stats.DnsCountByRcode == nil {
				stats.DnsCountByRcode = make(map[uint32]uint32)
			}
			err = m.handleDNSCountByRcode(stats.DnsCountByRcode, value)
		default:
			return false, fmt.Errorf("unknown DNSStats field number %d", fieldNum)
		}
		return err == nil, err
	})
}

func (m *moleculeDecoder) handleDNSCountByRcode(dnsMap map[uint32]uint32, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.dnsRcodeBuffer.Reset(buf)

	var key uint32
	var val uint32
	err = molecule.MessageEach(m.dnsRcodeBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsUint32()
		case 2:
			val, err = value.AsUint32()
		}
		return err == nil, err
	})
	if err != nil {
		return err
	}
	dnsMap[key] = val
	return nil
}

func (m *moleculeDecoder) handleIPTranslation(value molecule.Value) (*model.IPTranslation, error) {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return nil, err
	}
	m.miscBuffer.Reset(buf)

	t := ipTranslationPool.Get().(*model.IPTranslation)

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // ReplSrcIP
			t.ReplSrcIP, err = value.AsStringUnsafe()
		case 2: // ReplDstIP
			t.ReplDstIP, err = value.AsStringUnsafe()
		case 3: // ReplSrcPort
			t.ReplSrcPort, err = value.AsInt32()
		case 4: // ReplDstPort
			t.ReplDstPort, err = value.AsInt32()
		default:
			return false, fmt.Errorf("unknown IPTranslation field number %d", fieldNum)
		}
		return err == nil, err
	})
	if err != nil {
		t.Reset()
		ipTranslationPool.Put(t)
		return nil, err
	}
	return t, nil
}

func (m *moleculeDecoder) handleAddr(value molecule.Value) (*model.Addr, error) {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return nil, err
	}
	m.miscBuffer.Reset(buf)

	addr := addrPool.Get().(*model.Addr)

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 2: // Ip
			addr.Ip, err = value.AsStringUnsafe()
		case 3: // Port
			addr.Port, err = value.AsInt32()
		case 5: // ContainerId
			addr.ContainerId, err = value.AsStringUnsafe()
		default:
			return false, fmt.Errorf("unknown Addr field number %d", fieldNum)
		}
		return err == nil, err
	})
	if err != nil {
		addr.Reset()
		addrPool.Put(addr)
		return nil, err
	}
	return addr, nil
}

func (m *moleculeDecoder) handleDNS(conns *model.Connections, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.miscBuffer.Reset(buf)

	if conns.Dns == nil {
		conns.Dns = make(map[string]*model.DNSEntry)
	}

	var key string
	val := dnsEntryPool.Get().(*model.DNSEntry)

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsStringUnsafe()
		case 2:
			err = m.handleDNSEntry(val, value)
		}
		return err == nil, err
	})
	if err != nil {
		val.Names = val.Names[:0]
		dnsEntryPool.Put(val)
		return err
	}
	conns.Dns[key] = val
	return nil
}

func (m *moleculeDecoder) handleDNSEntry(dns *model.DNSEntry, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.dnsEntryBuffer.Reset(buf)
	return molecule.MessageEach(m.dnsEntryBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		switch fieldNum {
		case 1:
			name, err := value.AsStringUnsafe()
			if err != nil {
				return false, err
			}
			dns.Names = append(dns.Names, name)
		default:
			return false, fmt.Errorf("unknown DNSEntry field number %d", fieldNum)
		}
		return true, nil
	})
}

func (m *moleculeDecoder) handleRoutes(conns *model.Connections, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.routeBuffer.Reset(buf)

	r := routePool.Get().(*model.Route)

	err = molecule.MessageEach(m.routeBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // Subnet
			r.Subnet, err = m.handleSubnet(value)
		default:
			return false, fmt.Errorf("unknown Route field number %d", fieldNum)
		}
		return err == nil, err
	})
	if err != nil {
		r.Reset()
		routePool.Put(r)
		return err
	}
	conns.Routes = append(conns.Routes, r)
	return nil
}

func (m *moleculeDecoder) handleSubnet(value molecule.Value) (*model.Subnet, error) {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return nil, err
	}
	m.miscBuffer.Reset(buf)

	s := subnetPool.Get().(*model.Subnet)

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // Alias
			s.Alias, err = value.AsStringUnsafe()
		default:
			return false, fmt.Errorf("unknown Subnet field number %d", fieldNum)
		}
		return err == nil, err
	})
	if err != nil {
		s.Reset()
		subnetPool.Put(s)
		return nil, err
	}
	return s, err
}

func (m *moleculeDecoder) handleAgentConfiguration(value molecule.Value) (*model.AgentConfiguration, error) {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return nil, err
	}
	m.miscBuffer.Reset(buf)

	ac := agentConfigPool.Get().(*model.AgentConfiguration)

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // NpmEnabled
			ac.NpmEnabled, err = value.AsBool()
		case 2: // TsmEnabled
			ac.TsmEnabled, err = value.AsBool()
		default:
			return false, fmt.Errorf("unknown AgentConfiguration field number %d", fieldNum)
		}
		return err == nil, err
	})
	return ac, err
}

func (m *moleculeDecoder) handleCompilationTelemetryByAsset(conns *model.Connections, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.miscBuffer.Reset(buf)

	var key string
	val := rcTelemetryPool.Get().(*model.RuntimeCompilationTelemetry)

	if conns.CompilationTelemetryByAsset == nil {
		conns.CompilationTelemetryByAsset = make(map[string]*model.RuntimeCompilationTelemetry)
	}

	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsStringUnsafe()
		case 2:
			err = m.handleRuntimeCompilationTelemetry(val, value)
		}
		return err == nil, err
	})
	if err != nil {
		val.Reset()
		rcTelemetryPool.Put(val)
		return err
	}
	conns.CompilationTelemetryByAsset[key] = val
	return nil
}

func (m *moleculeDecoder) handleRuntimeCompilationTelemetry(rc *model.RuntimeCompilationTelemetry, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.rcTelemetryBuffer.Reset(buf)
	return molecule.MessageEach(m.rcTelemetryBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1: // RuntimeCompilationEnabled
			rc.RuntimeCompilationEnabled, err = value.AsBool()
		case 2: // RuntimeCompilationResult
			ev, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			rc.RuntimeCompilationResult = model.RuntimeCompilationResult(ev)
		case 3: // RuntimeCompilationDuration
			rc.RuntimeCompilationDuration, err = value.AsInt64()
		case 4: // KernelHeaderFetchResult
			ev, err := value.AsInt32()
			if err != nil {
				return false, err
			}
			rc.KernelHeaderFetchResult = model.KernelHeaderFetchResult(ev)
		default:
			return false, fmt.Errorf("unknown RuntimeCompilationTelemetry field number %d", fieldNum)
		}
		return err == nil, err
	})
}

func (m *moleculeDecoder) handleConnTelemetryMap(conns *model.Connections, value molecule.Value) error {
	buf, err := value.AsBytesUnsafe()
	if err != nil {
		return err
	}
	m.miscBuffer.Reset(buf)

	if conns.ConnTelemetryMap == nil {
		conns.ConnTelemetryMap = make(map[string]int64)
	}

	var key string
	var val int64
	err = molecule.MessageEach(m.miscBuffer, func(fieldNum int32, value molecule.Value) (bool, error) {
		var err error
		switch fieldNum {
		case 1:
			key, err = value.AsStringUnsafe()
		case 2:
			val, err = value.AsInt64()
		}
		return err == nil, err
	})
	if err != nil {
		return err
	}
	conns.ConnTelemetryMap[key] = val
	return nil
}

func decodeStringSlice(s []string, value molecule.Value) ([]string, error) {
	v, err := value.AsStringUnsafe()
	if err != nil {
		return nil, err
	}
	s = append(s, v)
	return s, nil
}
