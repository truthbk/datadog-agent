// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package testutil

/*
#include "tun.h"
*/
import "C"
import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func CreateTun(t *testing.T, name, addr string) *os.File {
	t.Helper()

	fd := C.create_tap(C.CString(name))
	require.GreaterOrEqual(t, int(fd), 0, "could not create tap")

	err := exec.Command("ip", "link", "set", "up", name).Run()
	require.NoErrorf(t, err, "could not set interface up")

	err = exec.Command("ip", "addr", "add", addr, "dev", name).Run()
	require.NoErrorf(t, err, "could not set interface address")

	return os.NewFile(uintptr(fd), "tap-test")
}

func SetARP(t *testing.T, addr, mac string) {
	t.Helper()

	err := exec.Command("arp", "-s", addr, mac).Run()
	require.NoErrorf(t, err, "could not set ARP entry")
}
