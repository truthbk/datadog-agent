// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package statsd

import (
	"fmt"

	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
)

// findAddr finds the correct address to connect to the Dogstatsd server.
func findAddr(conf *config.Config) (string, error) {
	if conf.StatsdSocket != "" {
		// Unix sockets can be used
		return `unix://` + conf.StatsdSocket, nil
	}
	if conf.StatsdPort > 0 {
		// UDP enabled
		return fmt.Sprintf("%s:%d", conf.StatsdHost, conf.StatsdPort), nil
	}
	return "", fmt.Errorf("dogstatsd_port is set to 0 and no alternative is available")
}
