// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi = windows.NewLazySystemDLL("wevtapi.dll")
	evtSubscribe = wevtapi.NewProc("EvtSubscribe")
	evtClose = wevtapi.NewProc("EvtClose")
	evtNext = wevtapi.NewProc("EvtNext")
)

const (
	// EVT_SUBSCRIBE_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags
    EvtSubscribeToFutureEvents = 1
    EvtSubscribeStartAtOldestRecord = 2
    EvtSubscribeStartAfterBookmark = 3
    EvtSubscribeOriginMask = 3
    EvtSubscribeTolerateQueryErrors = 0x1000
    EvtSubscribeStrict = 0x10000
)

// Returned from EvtQuery and EvtSubscribe
type EventResultSetHandle windows.Handle

// Returned from EvtNext
type EventRecordHandle windows.Handle

// Returned from CreateEvent
type WaitEventHandle windows.Handle

// Pass returned handle to EvtClose
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
func EvtSubscribe(
	SignalEvent WaitEventHandle,
	ChannelPath string,
	Query string,
	Flags uint) (EventResultSetHandle, error) {

	// Convert Go string to Windows API string
	channelPath, err := windows.UTF16PtrFromString(ChannelPath)
	if err != nil {
		return EventResultSetHandle(0), err
	}
	query, err := windows.UTF16PtrFromString(Query)
	if err != nil {
		return EventResultSetHandle(0), err
	}

	// Call API
	r1, _, lastErr := evtSubscribe.Call(
		uintptr(0), // TODO: localhost only for now
		uintptr(SignalEvent),
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		uintptr(0), // TODO: no bookmarks for now
		uintptr(0), // No context in pull mode
		uintptr(0), // No callback in pull mode
		uintptr(Flags))
	// EvtSubscribe returns NULL on error
	if r1 == 0 {
		return EventResultSetHandle(0), lastErr
	}

	return EventResultSetHandle(r1), nil
}

// Must call EvtClose on every handle returned
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext
func EvtNext(
	Session EventResultSetHandle,
	EventsArray []EventRecordHandle,
	EventsSize uint,
	Timeout uint) ([]EventRecordHandle, error) {

	var Returned uint32
	Returned = 0

	// Fill array
	r1, _, lastErr := evtNext.Call(
		uintptr(Session),
		uintptr(EventsSize),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(&EventsArray[:1][0])),
		uintptr(Timeout),
		uintptr(0), // reserved must be 0
		uintptr(unsafe.Pointer(&Returned)))
	// EvtNext returns C BOOL FALSE (0) on "error"
	// "error" can mean error, ERROR_TIMEOUT, or ERROR_NO_MORE_ITEMS
	if r1 == 0 {
		return nil, lastErr
	}

	// Trim slice over returned # elements
	return EventsArray[:Returned], nil
}

func EvtCloseResultSet(h EventResultSetHandle) {
	EvtClose(windows.Handle(h))
}

func EvtCloseRecord(h EventRecordHandle) {
	EvtClose(windows.Handle(h))
}

func EvtClose(h windows.Handle) {
	if h != windows.Handle(0) {
		evtClose.Call(uintptr(h))
	}
}

func safeCloseNullHandle(h windows.Handle) {
	if h != windows.Handle(0) {
		windows.CloseHandle(h)
	}
}
