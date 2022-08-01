// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package statsd exposes utilities for setting up and using a sub-set of Datadog's dogstatsd
// client.
package statsd

import (
	"github.com/DataDog/datadog-go/v5/statsd"

	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
)

// Client is a global Statsd client. When a client is configured via Configure,
// that becomes the new global Statsd client in the package.
var Client *statsd.Client

// Configure creates a statsd client for the given agent's configuration, using the specified global tags.
func Configure(conf *config.Config, tags []string) error {
	addr, err := findAddr(conf)
	if err != nil {
		return err
	}
	client, err := statsd.New(addr, statsd.WithTags(tags))
	if err != nil {
		return err
	}
	Client = client
	return nil
}
