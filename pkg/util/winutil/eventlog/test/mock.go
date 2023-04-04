// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog_test

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/mock"
)

// MockAPITester uses a mock of the Windows EventLog APIs
// and provides utilities to the test framework that will simulate
// behavior and not make any changes to the host system
type MockAPITester struct {
	t           testing.TB
	eventlogapi *mockevtapi.API
}

func NewMockAPITester(t testing.TB) *MockAPITester {
	var ti MockAPITester
	ti.t = t
	ti.eventlogapi = mockevtapi.New()
	return &ti
}

func (ti *MockAPITester) Name() string {
	return "Mock"
}

func (ti *MockAPITester) T() testing.TB {
	return ti.t
}

func (ti *MockAPITester) API() evtapi.API {
	return ti.eventlogapi
}

func (ti *MockAPITester) InstallChannel(channel string) error {
	return ti.eventlogapi.AddEventLog(channel)
}

func (ti *MockAPITester) RemoveChannel(channel string) error {
	return ti.eventlogapi.RemoveEventLog(channel)
}

func (ti *MockAPITester) InstallSource(channel string, source string) error {
	return ti.eventlogapi.AddEventSource(channel, source)
}

func (ti *MockAPITester) RemoveSource(channel string, source string) error {
	return ti.eventlogapi.RemoveEventSource(channel, source)
}

func (ti *MockAPITester) GenerateEvents(channelName string, numEvents uint) error {
	return ti.eventlogapi.GenerateEvents(channelName, numEvents)
}
