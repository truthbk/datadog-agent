// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm
// +build windows,npm

package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

func TestNonLocalScenario(t *testing.T) {
	assert := assert.New(t)
	localAddrString := "1.1.1.1"
	remoteAddrString := "2.2.2.2"
	connections := []network.ConnectionStats{
		{
			// I am clieant of remote server
			Source: util.AddressFromString(localAddrString),
			SPort:  60000,
			Dest:   util.AddressFromString(remoteAddrString),
			DPort:  80,
			Pid:    1,
		},
		{
			// I am server of remote client
			Source: util.AddressFromString(localAddrString),
			SPort:  80,
			Dest:   util.AddressFromString(remoteAddrString),
			DPort:  60001,
			Pid:    2,
		},
	}
	var clientStats http.RequestStats
	clientKey := http.NewKey(
		util.AddressFromString(localAddrString),
		util.AddressFromString(remoteAddrString),
		60000,
		80,
		"/",
		true,
		http.MethodGet,
	)
	clientStats.AddRequest(100, 1.0, 0, []string{"service:client"})

	serverKey := http.NewKey(
		util.AddressFromString(localAddrString),
		util.AddressFromString(remoteAddrString),
		80,
		60001,
		"/",
		true,
		http.MethodGet,
	)
	var serverStats http.RequestStats
	serverStats.AddRequest(100, 1.0, 0, []string{"service:server"})

	in := &network.Connections{
		BufferedData: network.BufferedData{
			Conns: connections,
		},
		HTTP: map[http.Key]*http.RequestStats{
			clientKey: &clientStats,
			serverKey: &serverStats,
		},
	}

	httpEncoder := newHTTPEncoder(in)

	// assert that each end of the connection has its own HTTP stat object
	// client-server connection
	aggregations, _, dynamicTags := httpEncoder.GetHTTPAggregationsAndTags(connections[0])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)
	assert.Equal(map[string]struct{}{"service:client": {}}, dynamicTags)

	// server-client connection
	aggregations, _, dynamicTags = httpEncoder.GetHTTPAggregationsAndTags(connections[1])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)
	assert.Equal(map[string]struct{}{"service:server": {}}, dynamicTags)
}

func TestLocalhostScenario(t *testing.T) {
	assert := assert.New(t)
	connections := []network.ConnectionStats{
		{
			// client
			Source: util.AddressFromString("127.0.0.1"),
			SPort:  60000,
			Dest:   util.AddressFromString("127.0.0.1"),
			DPort:  80,
			Pid:    1,
		},
		{
			// server
			Source: util.AddressFromString("127.0.0.1"),
			SPort:  80,
			Dest:   util.AddressFromString("127.0.0.1"),
			DPort:  60000,
			Pid:    2,
		},
	}

	var clientStats http.RequestStats
	clientKey := http.NewKey(
		util.AddressFromString("127.0.0.1"),
		util.AddressFromString("127.0.0.1"),
		60000,
		80,
		"/",
		true,
		http.MethodGet,
	)
	clientStats.AddRequest(100, 1.0, 0, []string{"service:client"})

	serverKey := http.NewKey(
		util.AddressFromString("127.0.0.1"),
		util.AddressFromString("127.0.0.1"),
		80,
		60000,
		"/",
		true,
		http.MethodGet,
	)
	var serverStats http.RequestStats
	serverStats.AddRequest(100, 1.0, 0, []string{"service:server"})

	in := &network.Connections{
		BufferedData: network.BufferedData{
			Conns: connections,
		},
		HTTP: map[http.Key]*http.RequestStats{
			clientKey: &clientStats,
			serverKey: &serverStats,
		},
	}

	httpEncoder := newHTTPEncoder(in)

	// assert that each end of the connection has its own HTTP stat object
	// client-server connection
	aggregations, _, dynamicTags := httpEncoder.GetHTTPAggregationsAndTags(connections[0])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)
	assert.Equal(map[string]struct{}{"service:client": {}}, dynamicTags)

	// server-client connection
	aggregations, _, dynamicTags = httpEncoder.GetHTTPAggregationsAndTags(connections[1])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)
	assert.Equal(map[string]struct{}{"service:server": {}}, dynamicTags)
}
