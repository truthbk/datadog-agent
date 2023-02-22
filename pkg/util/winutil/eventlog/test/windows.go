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

	"golang.org/x/sys/windows/svc/eventlog"

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    winevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
)

// WindowsTestInterface uses the real Windows EventLog APIs
// and provides utilities to the test framework that will modify
// the host system (e.g. install event log source, generate events).
type WindowsTestInterface struct {
	t testing.TB
	eventlogapi *winevtapi.WindowsEventLogAPI
}

func NewWindowsTestInterface(t testing.TB) *WindowsTestInterface {
	var ti WindowsTestInterface
	ti.t = t
	ti.eventlogapi = winevtapi.NewWindowsEventLogAPI()
	return &ti
}

func (ti *WindowsTestInterface) Name() string{
	return "Windows"
}

func (ti *WindowsTestInterface) T() testing.TB {
	return ti.t
}

func (ti *WindowsTestInterface) EventLogAPI() evtapidef.IWindowsEventLogAPI {
	return ti.eventlogapi
}

func (ti *WindowsTestInterface) InstallSource(name string) error {
	return fmt.Errorf("not implemented")
}

func (ti *WindowsTestInterface) RemoveSource(name string) error {
	return fmt.Errorf("not implemented")
}

func (ti *WindowsTestInterface) GenerateEvents(channelName string, numEvents uint) error {
	return fmt.Errorf("not implemented")
}
