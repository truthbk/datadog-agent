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

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"

	"github.com/stretchr/testify/require"
)

type EventLogTestInterface interface {
	Name() string
	T() testing.TB
	EventLogAPI() evtapidef.IWindowsEventLogAPI
	InstallSource(name string) error
	RemoveSource(name string) error
	GenerateEvents(channelName string, numEvents uint) error
}

func GetEnabledTestInterfaces() []string {

	var ti []string

	// mock API
	ti = append(ti, "Mock")

	if testing.Short() == false {
		// Windows API
		ti = append(ti, "Windows")
	}

	return ti
}

func GetTestInterfaceByName(name string, t testing.TB) EventLogTestInterface {
	if name == "Mock" {
		return NewMockTestInterface(t)
	} else if name == "Windows" {
		if testing.Short() {
			t.Skip("Skipping Windows API")
		}
		return NewWindowsTestInterface(t)
	}

	require.FailNow(t, fmt.Sprintf("invalid test interface: %v", name))
	return nil
}

