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
	t *testing.T
	eventlogapi *mockevtapi.MockWindowsEventLogAPI
}

func NewMockTestInterface(t *testing.T) *MockTestInterface {
	var ti MockTestInterface
	ti.t = t
	ti.eventlogapi = mockevtapi.NewMockWindowsEventLogAPI()
	return &ti
}

func (ti *MockTestInterface) Name() string{
	return "Mock"
}

func (ti *MockTestInterface) T() *testing.T {
	return ti.t
}

func (ti *MockTestInterface) EventLogAPI() evtapidef.IWindowsEventLogAPI {
	return ti.eventlogapi
}

func (ti *MockTestInterface) InstallSource(name string) error {
	return ti.eventlogapi.AddEventLog(name)
}

func (ti *MockTestInterface) RemoveSource(name string) error {
	return nil
}

func (ti *MockTestInterface) GenerateEvents(channelName string, numEvents uint) error {
	return ti.eventlogapi.GenerateEvents(channelName, numEvents)
}

