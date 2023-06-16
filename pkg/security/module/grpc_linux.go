// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package module

import (
	"fmt"
	"net"
	"os"
)

func (g *GRPCServer) getListener() (net.Listener, error) {
	ln, err := net.Listen("unix", g.socketPath)
	if err != nil {
		return nil, fmt.Errorf("unable to create runtime security socket: %w", err)
	}

	if err := os.Chmod(g.socketPath, 0700); err != nil {
		return nil, fmt.Errorf("unable to create runtime security socket: %w", err)
	}

	return ln, nil
}
