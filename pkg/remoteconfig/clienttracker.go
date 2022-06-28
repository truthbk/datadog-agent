// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package remoteconfig

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/proto/pbgo"
)

type client struct {
	lastSeen time.Time
	pbClient *pbgo.Client
}

func (c *client) expired(timestamp time.Time, ttl time.Duration) bool {
	return timestamp.After(c.lastSeen.Add(ttl))
}

type clientTracker struct {
	clientsTTL time.Duration
	clients    map[string]*client
}

func newClientTracker(clientsTTL time.Duration) *clientTracker {
	return &clientTracker{
		clientsTTL: clientsTTL,
		clients:    make(map[string]*client),
	}
}

// seen marks the given client as active
func (c *clientTracker) seen(pbClient *pbgo.Client, timestamp time.Time) {
	pbClient.LastSeen = uint64(timestamp.UnixMilli())
	c.clients[pbClient.Id] = &client{
		lastSeen: timestamp,
		pbClient: pbClient,
	}
}

// ActiveClients returns the list of active clients as of the given time
func (c *clientTracker) activeClients(timestamp time.Time) []*pbgo.Client {
	var activeClients []*pbgo.Client
	for id, client := range c.clients {
		if client.expired(timestamp, c.clientsTTL) {
			delete(c.clients, id)
			continue
		}
		activeClients = append(activeClients, client.pbClient)
	}
	return activeClients
}
