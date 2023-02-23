// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog_test

import (
	"testing"

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    mockevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/mock"
)

// MockTestInterface uses a mock of the Windows EventLog APIs
// and provides utilities to the test framework that will simulate
// behavior and not make any changes to the host system
type MockTestInterface struct {
	t testing.TB
	eventlogapi *mockevtapi.MockWindowsEventLogAPI
}

func NewMockTestInterface(t testing.TB) *MockTestInterface {
	var ti MockTestInterface
	ti.t = t
	ti.eventlogapi = mockevtapi.NewMockWindowsEventLogAPI()
	return &ti
}

func (ti *MockTestInterface) Name() string{
	return "Mock"
}

func (ti *MockTestInterface) T() testing.TB {
	return ti.t
}

func (ti *MockTestInterface) EventLogAPI() evtapidef.IWindowsEventLogAPI {
	return ti.eventlogapi
}

func (ti *MockTestInterface) InstallChannel(channel string) error {
	return ti.eventlogapi.AddEventLog(channel)
}

func (ti *MockTestInterface) RemoveChannel(channel string) error {
	return ti.eventlogapi.RemoveEventLog(channel)
}

func (ti *MockTestInterface) InstallSource(channel string, source string) error {
	// not needed
	return nil
}

func (ti *MockTestInterface) RemoveSource(channel string, source string) error {
	// not needed
	return nil
}

func (ti *MockTestInterface) GenerateEvents(channelName string, numEvents uint) error {
	return ti.eventlogapi.GenerateEvents(channelName, numEvents)
}

