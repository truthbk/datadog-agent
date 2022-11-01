// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package statsd

import (
	"fmt"

	"github.com/DataDog/datadog-go/v5/statsd"

	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
)

const (
	statsdPoolSize = 64
)

// Client is a global Statsd client. When a client is configured via Configure,
// that becomes the new global Statsd client in the package.
var Client *statsd.Client

// GetAddr finds the correct address to connect to the Dogstatsd server.
func GetAddr(conf *config.Config) string {
	if conf.StatsdPort > 0 {
		// UDP enabled
		return fmt.Sprintf("%s:%d", conf.StatsdHost, conf.StatsdPort)
	}
	if conf.StatsdPipeName != "" {
		// Windows Pipes can be used
		return `\\.\pipe\` + conf.StatsdPipeName
	}
	if conf.StatsdSocket != "" {
		// Unix sockets can be used
		return `unix://` + conf.StatsdSocket
	}
	return ""
}

// Configure creates a statsd client for the given agent's configuration
func Configure(conf *config.Config) error {
	addr := GetAddr(conf)
	if addr == "" {
		return fmt.Errorf("dogstatsd_port is set to 0 and no alternative is available")
	}
	_, err := Create(addr)
	return err
}

// Create creates a statsd client using the given address, only if the global client has not been created.
func Create(addr string) (statsd.ClientInterface, error) {
	if Client != nil {
		return Client, nil
	}
	client, err := statsd.New(addr, statsd.WithBufferPoolSize(statsdPoolSize))
	if err != nil {
		return nil, err
	}
	Client = client
	return Client, nil
}
