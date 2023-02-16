// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package mock

import (
	"fmt"

    evtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"

	"golang.org/x/sys/windows"
)

type MockWindowsEventLogAPI struct {
	name string
	subscriptionHandleCount uint
	eventLogs map[string]*mockEventLog
	subscriptions map[evtapi.EventResultSetHandle]*mockSubscription
}

type mockEventLog struct {
	name string
	events []*mockEventRecord
}

type mockSubscription struct {
	channel string
	query string
	handle evtapi.EventResultSetHandle

	nextEvent uint
}

type mockEventRecord struct {
	handle evtapi.EventRecordHandle
	eventID uint
	source string
	data string
}

func NewMockWindowsEventLogAPI() *MockWindowsEventLogAPI {
	var api MockWindowsEventLogAPI
	api.name = "Mock"

	api.subscriptions = make(map[evtapi.EventResultSetHandle]*mockSubscription)
	// invalid handle
	api.subscriptions[0] = nil

	api.eventLogs = make(map[string]*mockEventLog)

	return &api
}

func (api *MockWindowsEventLogAPI) API_Name() string {
	return api.name
}

func newMockEventLog(name string) *mockEventLog {
	var e mockEventLog
	e.name = name
	return &e
}

func newMockSubscription(channel string, query string) *mockSubscription {
	var s mockSubscription
	s.channel = channel
	s.query = query
	return &s
}

func newMockEventRecord(eventID uint, source string, data string) *mockEventRecord {
	var e mockEventRecord
	e.eventID = eventID
	e.source = source
	e.data = data
	return &e
}

//
// Mock helpers
//
func (api *MockWindowsEventLogAPI) AddEventLog(name string) error {
	// does it exist
	_, err := api.getMockEventLog(name)
	if err == nil {
		return fmt.Errorf("Event log %v already exists", name)
	}

	api.addMockEventLog(newMockEventLog(name))
	return nil
}

func (api *MockWindowsEventLogAPI) GenerateEvents(eventLogName string, numEvents uint) error {
	// Get event log
	eventLog, err := api.getMockEventLog(eventLogName)
	if err != nil {
		return err
	}

	// Add junk events
	for i := uint(0); i < numEvents; i+=1 {
		event := newMockEventRecord(1000, "testchannel", "testdata")
		eventLog.addEvent(event)
	}

	return nil
}

//
// internal mock functions
//
func (api *MockWindowsEventLogAPI) addSubscription(sub *mockSubscription) {
	api.subscriptionHandleCount += 1
	h := api.subscriptionHandleCount
	sub.handle = evtapi.EventResultSetHandle(h)
	api.subscriptions[sub.handle] = sub
}

func (api *MockWindowsEventLogAPI) getMockSubscriptionByHandle(subHandle evtapi.EventResultSetHandle) (*mockSubscription, error) {
	v, ok := api.subscriptions[subHandle]
	if !ok {
		return nil, fmt.Errorf("Subscription not found: %#x", subHandle)
	}
	return v, nil
}

func (api *MockWindowsEventLogAPI) getMockEventLog(name string) (*mockEventLog, error) {
	v, ok := api.eventLogs[name]
	if !ok {
		return nil, fmt.Errorf("Event log %v not found", name)
	}
	return v, nil
}

func (api *MockWindowsEventLogAPI) addMockEventLog(eventLog *mockEventLog) {
	api.eventLogs[eventLog.name] = eventLog
}

func (e *mockEventLog) addEvent(event *mockEventRecord) {
	e.events = append(e.events, event)
	event.handle = evtapi.EventRecordHandle(len(e.events))
}

//
// Mock Windows APIs
//
func (api *MockWindowsEventLogAPI) EvtSubscribe(
	SignalEvent evtapi.WaitEventHandle,
	ChannelPath string,
	Query string,
	Bookmark evtapi.EventBookmarkHandle,
	Flags uint) (evtapi.EventResultSetHandle, error) {

	if Query != "" && Query != "*" {
		return evtapi.EventResultSetHandle(0), fmt.Errorf("Mock does not support query syntax")
	}

	// ensure channel exists
	_, err := api.getMockEventLog(ChannelPath)
	if err != nil {
		return evtapi.EventResultSetHandle(0), err
	}

	// create sub
	sub := newMockSubscription(ChannelPath, Query)
	api.addSubscription(sub)
	return sub.handle, nil
}

func (api *MockWindowsEventLogAPI) EvtNext(
	Session evtapi.EventResultSetHandle,
	EventsArray []evtapi.EventRecordHandle,
	EventsSize uint,
	Timeout uint) ([]evtapi.EventRecordHandle, error) {

	// get subscription
	sub, err := api.getMockSubscriptionByHandle(Session)
	if err != nil {
		return nil, err
	}

	// get event log
	eventLog, err := api.getMockEventLog(sub.channel)
	if err != nil {
		return nil, err
	}

	// is event log empty
	if len(eventLog.events) == 0 {
		return nil, windows.ERROR_NO_MORE_ITEMS
	}
	// if we are at end
	if sub.nextEvent >= uint(len(eventLog.events)) {
		return nil, windows.ERROR_NO_MORE_ITEMS
	}

	// get next events from log
	end := sub.nextEvent+EventsSize
	if end > uint(len(eventLog.events)) {
		end = uint(len(eventLog.events))
	}
	events := eventLog.events[sub.nextEvent:end]
	eventHandles := make([]evtapi.EventRecordHandle, len(events))
	for i, e := range events {
		eventHandles[i] = e.handle
	}
	sub.nextEvent = end

	return eventHandles, nil
}

func (api *MockWindowsEventLogAPI) EvtClose(h windows.Handle) {
	// nothing to do
}

