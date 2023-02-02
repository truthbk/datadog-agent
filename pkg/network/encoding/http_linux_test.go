// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

func TestLocalhostScenario(t *testing.T) {
	assert := assert.New(t)
	connections := []network.ConnectionStats{
		{
			Source: util.AddressFromString("127.0.0.1"),
			SPort:  60000,
			Dest:   util.AddressFromString("127.0.0.1"),
			DPort:  80,
			Pid:    1,
		},
		{
			Source: util.AddressFromString("127.0.0.1"),
			SPort:  80,
			Dest:   util.AddressFromString("127.0.0.1"),
			DPort:  60000,
			Pid:    2,
		},
	}

	var httpStats http.RequestStats
	httpKey := http.NewKey(
		util.AddressFromString("127.0.0.1"),
		util.AddressFromString("127.0.0.1"),
		60000,
		80,
		"/",
		true,
		http.MethodGet,
	)
	httpStats.AddRequest(100, 1.0, 0, nil)

	in := &network.Connections{
		BufferedData: network.BufferedData{
			Conns: connections,
		},
		HTTP: map[http.Key]*http.RequestStats{
			httpKey: &httpStats,
		},
	}

	httpEncoder := newHTTPEncoder(in)

	// assert that both ends (client:server, server:client) of the connection
	// will have HTTP stats
	aggregations, _, _ := httpEncoder.GetHTTPAggregationsAndTags(connections[0])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)

	aggregations, _, _ = httpEncoder.GetHTTPAggregationsAndTags(connections[1])
	assert.NotNil(aggregations)
	assert.Equal("/", aggregations.EndpointAggregations[0].Path)
	assert.Equal(uint32(1), aggregations.EndpointAggregations[0].StatsByResponseStatus[0].Count)
}
