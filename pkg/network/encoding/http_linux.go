// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package encoding

import (
	model "github.com/DataDog/agent-payload/v5/process"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
)

// matcher provides a Linux-specific implementation of a requestMatcher
// There are a couple of caveats worth mentioning here:
// 1) In Linux HTTP data is always indexed in normalized (client, server) form;
// 2) When both client and server are in the same host, there is only one
//    HTTPAggregation representing it, which gets associated to both (client,
//    server) and (server, client)
// 3) There is a tricky PID collision scenario also addressed here which stems from
//    the fact that we have no access to PIDs from socket filters.
//    This means that, for example, a NGINX server with 3 workers (which are forked
//    processes) may produce the following set of connection tuples:
//    a: src, dst, PID 1
//    b: src, dst, PID 2
//    c: src, dst, PID 3
//    The issue is, they will all produce the same http.KeyTuple (which doesn't have PID)
//    and would all "claim" the same HTTPAggregations object which would result
//    in over-counting requests. This is avoided here by randomly
//    assigning the HTTPAggregations to the first connection to "claim" it.
type matcher struct {
	aggregations map[http.KeyTuple]*aggregationWrapper
}

// aggregationWrapper is meant to handle collision scenarios where multiple
// `ConnectionStats` objects may claim the same `HTTPAggregations` object because
// they generate the same http.KeyTuple
// TODO: we should probably revist/get rid of this if we ever replace socket
// filters by kprobes, since in that case we would have access to PIDs, and
// could incorporate that information in the `http.KeyTuple` struct.
type aggregationWrapper struct {
	*model.HTTPAggregations

	// we keep track of the source and destination ports of the first
	// `ConnectionStats` to claim this `HTTPAggregations` object
	sport, dport uint16
}

func newRequestMatcher() requestMatcher {
	m := new(matcher)
	return m.Match
}

func (m *matcher) Match(e *httpEncoder, c network.ConnectionStats) (*model.HTTPAggregations, uint64, map[string]struct{}) {
	m.init(e)
	k, a := m.getAggregation(c)
	if a == nil {
		return nil, 0, nil
	}

	if a.sport == 0 && a.dport == 0 {
		// This is the first time a ConnectionStats claim this aggregation. In
		// this case we return the value and save the source and destination
		// ports
		a.sport = c.SPort
		a.dport = c.DPort
		return a.HTTPAggregations, e.staticTags[k], e.dynamicTagsSet[k]
	}

	if c.SPort == a.dport && c.DPort == a.sport {
		// We have have a collision with another `ConnectionStats`, but this is a
		// legit scenario where we're dealing with the opposite ends of the
		// same connection, which means both server and client are in the same host.
		// In this particular case it is correct to have both connections
		// (client:server and server:client) referencing the same HTTP data.
		return a.HTTPAggregations, e.staticTags[k], e.dynamicTagsSet[k]
	}

	// Return nil otherwise. This is to prevent multiple `ConnectionStats` with
	// exactly the same source and destination addresses but different PIDs to
	// "bind" to the same HTTPAggregations object, which would result in a
	// overcount problem. (Note that this is due to the fact that
	// `http.KeyTuple` doesn't have a PID field.) This happens mostly in the
	// context of pre-fork web servers, where multiple worker proceses share the
	// same socket
	return nil, 0, nil
}

func (m *matcher) init(e *httpEncoder) {
	if m.aggregations != nil {
		return
	}

	m.aggregations = make(map[http.KeyTuple]*aggregationWrapper, len(e.aggregations))
	for k, v := range e.aggregations {
		m.aggregations[k] = &aggregationWrapper{
			HTTPAggregations: v,
		}
	}
}

func (m *matcher) getAggregation(c network.ConnectionStats) (http.KeyTuple, *aggregationWrapper) {
	for _, k := range network.HTTPKeyTuplesFromConn(c) {
		if a, ok := m.aggregations[k]; ok {
			return k, a
		}
	}
	return http.KeyTuple{}, nil
}
