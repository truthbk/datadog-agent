// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog_test

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"

	"github.com/stretchr/testify/require"
)

type APITester interface {
	Name() string
	T() testing.TB
	API() evtapi.API
	InstallChannel(channel string) error
	RemoveChannel(channel string) error
	InstallSource(channel string, source string) error
	RemoveSource(channel string, name string) error
	GenerateEvents(channelName string, numEvents uint) error
}

func GetEnabledAPITesters() []string {

	var ti []string

	// mock API
	ti = append(ti, "Mock")

	if testing.Short() == false {
		// Windows API
		ti = append(ti, "Windows")
	}

	return ti
}

func GetAPITesterByName(name string, t testing.TB) APITester {
	if name == "Mock" {
		return NewMockAPITester(t)
	} else if name == "Windows" {
		if testing.Short() {
			t.Skip("Skipping Windows API")
		}
		return NewWindowsAPITester(t)
	}

	require.FailNow(t, fmt.Sprintf("invalid test interface: %v", name))
	return nil
}

