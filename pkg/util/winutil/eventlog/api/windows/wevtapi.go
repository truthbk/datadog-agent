// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package winevtapi

import (
	"fmt"
	"unsafe"

    "github.com/DataDog/datadog-agent/pkg/util/winutil"
    evtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"

	"golang.org/x/sys/windows"
)

var (
	// New Event Log API
	// https://learn.microsoft.com/en-us/windows/win32/wes/using-windows-event-log
	wevtapi = windows.NewLazySystemDLL("wevtapi.dll")
	evtSubscribe = wevtapi.NewProc("EvtSubscribe")
	evtClose = wevtapi.NewProc("EvtClose")
	evtNext = wevtapi.NewProc("EvtNext")
	evtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	evtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
	evtCreateRenderContext = wevtapi.NewProc("EvtCreateRenderContext")
	evtRender = wevtapi.NewProc("EvtRender")
	evtClearLog = wevtapi.NewProc("EvtClearLog")

	// Legacy Event Logging API
	// https://learn.microsoft.com/en-us/windows/win32/eventlog/using-event-logging
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	registerEventSource = advapi32.NewProc("RegisterEventSourceW")
	deregisterEventSource = advapi32.NewProc("DeregisterEventSource")
	reportEvent = advapi32.NewProc("ReportEventW")
)

type API struct {}

func New() *API {
	var api API
	return &api
}

// Pass returned handle to EvtClose
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
func (api *API) EvtSubscribe(
	SignalEvent evtapi.WaitEventHandle,
	ChannelPath string,
	Query string,
	Bookmark evtapi.EventBookmarkHandle,
	Flags uint) (evtapi.EventResultSetHandle, error) {

	// Convert Go string to Windows API string
	channelPath, err := winutil.UTF16PtrOrNilFromString(ChannelPath)
	if err != nil {
		return evtapi.EventResultSetHandle(0), err
	}
	query, err := winutil.UTF16PtrOrNilFromString(Query)
	if err != nil {
		return evtapi.EventResultSetHandle(0), err
	}

	// Call API
	r1, _, lastErr := evtSubscribe.Call(
		uintptr(0), // TODO: localhost only for now
		uintptr(SignalEvent),
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		uintptr(Bookmark),
		uintptr(0), // No context in pull mode
		uintptr(0), // No callback in pull mode
		uintptr(Flags))
	// EvtSubscribe returns NULL on error
	if r1 == 0 {
		return evtapi.EventResultSetHandle(0), lastErr
	}

	return evtapi.EventResultSetHandle(r1), nil
}

// Must call EvtClose on every handle returned
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext
func (api *API) EvtNext(
	Session evtapi.EventResultSetHandle,
	EventsArray []evtapi.EventRecordHandle,
	EventsSize uint,
	Timeout uint) ([]evtapi.EventRecordHandle, error) {

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

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose
func (api *API) EvtClose(h windows.Handle) {
	if h != windows.Handle(0) {
		evtClose.Call(uintptr(h))
	}
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreatebookmark
func EvtCreateBookmark(BookmarkXml string) (evtapi.EventBookmarkHandle, error) {
	var bookmarkXml *uint16

	bookmarkXml, err := winutil.UTF16PtrOrNilFromString(BookmarkXml)
	if err != nil {
		return evtapi.EventBookmarkHandle(0), err
	}

	r1, _, lastErr := evtCreateBookmark.Call(uintptr(unsafe.Pointer(bookmarkXml)))
	// EvtCreateBookmark returns NULL on error
	if r1 == 0 {
		return evtapi.EventBookmarkHandle(0), lastErr
	}

	return evtapi.EventBookmarkHandle(r1), nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtupdatebookmark
func EvtUpdateBookmark(Bookmark evtapi.EventBookmarkHandle, Event evtapi.EventRecordHandle) error {
	r1, _, lastErr := evtUpdateBookmark.Call(uintptr(Bookmark), uintptr(Event))
	// EvtUpdateBookmark returns C FALSE (0) on error
	if r1 == 0 {
		return lastErr
	}

	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreaterendercontext
func EvtCreateRenderContext(ValuePaths []string, Flags uint) (evtapi.EventRenderContextHandle, error) {
	var err error
	valuePaths := make([]*uint16, len(ValuePaths))

	for i, v := range ValuePaths {
		valuePaths[i], err = windows.UTF16PtrFromString(v)
		if err != nil {
			return evtapi.EventRenderContextHandle(0), err
		}
	}

	r1, _, lastErr := evtCreateRenderContext.Call(
		uintptr(len(valuePaths)),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(&valuePaths[:1][0])),
		uintptr(Flags))
	// EvtCreateRenderContext returns NULL on error
	if r1 == 0 {
		return evtapi.EventRenderContextHandle(0), lastErr
	}

	return evtapi.EventRenderContextHandle(r1), nil
}

// EvtRenderText supports the EvtRenderEventXml and EvtRenderBookmark Flags
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
func evtRenderText(
	Fragment windows.Handle,
	Flags uint) ([]uint16, error) {

	if Flags != evtapi.EvtRenderEventXml && Flags != evtapi.EvtRenderBookmark {
		return nil, fmt.Errorf("Invalid Flags")
	}

	// Get required buffer size
	var BufferUsed uint32
	var PropertyCount uint32
	r1, _, lastErr := evtRender.Call(
		uintptr(0),
		uintptr(Fragment),
		uintptr(Flags),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&BufferUsed)),
		uintptr(unsafe.Pointer(&PropertyCount)))
	// EvtRenders returns C FALSE (0) on error
	if r1 == 0 {
		if lastErr != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, lastErr
		}
	} else {
		return nil, nil
	}

	// Allocate buffer space (BufferUsed is size in bytes)
	Buffer := make([]uint16, BufferUsed/2)

	// Fill buffer
	r1, _, lastErr = evtRender.Call(
		uintptr(0),
		uintptr(Fragment),
		uintptr(Flags),
		uintptr(BufferUsed),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(&Buffer[:1][0])),
		uintptr(unsafe.Pointer(&BufferUsed)),
		uintptr(unsafe.Pointer(&PropertyCount)))
	// EvtRenders returns C FALSE (0) on error
	if r1 == 0 {
		return nil, lastErr
	}

	return Buffer, nil
}


// EvtRenderEventXmlText renders EvtRenderEventXml
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
func (api *API) EvtRenderEventXml(Fragment evtapi.EventRecordHandle) ([]uint16, error) {
	return evtRenderText(windows.Handle(Fragment), evtapi.EvtRenderEventXml)
}

// EvtRenderEventXmlText renders EvtRenderBookmark
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
func (api *API) EvtRenderBookmark(Fragment evtapi.EventBookmarkHandle) ([]uint16, error) {
	return evtRenderText(windows.Handle(Fragment), evtapi.EvtRenderBookmark)
}

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew
func (api *API) RegisterEventSource(SourceName string) (evtapi.EventSourceHandle, error) {
	sourceName, err := winutil.UTF16PtrOrNilFromString(SourceName)
	if err != nil {
		return evtapi.EventSourceHandle(0), err
	}

	r1, _, lastErr := registerEventSource.Call(
		uintptr(0), // local computer only
		uintptr(unsafe.Pointer(sourceName)))
	// RegisterEventSource returns NULL on error
	if r1 == 0 {
		return evtapi.EventSourceHandle(0), lastErr
	}

	return evtapi.EventSourceHandle(r1), nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deregistereventsource
func (api *API) DeregisterEventSource(EventLog evtapi.EventSourceHandle) error {
	r1, _, lastErr := deregisterEventSource.Call(uintptr(EventLog))
	// DeregisterEventSource returns C FALSE (0) on error
	if r1 == 0 {
		return lastErr
	}

	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
func (api *API) ReportEvent(
	EventLog evtapi.EventSourceHandle,
	Type uint,
	Category uint,
	EventID uint,
	Strings []string,
	RawData []uint8) error {

	var err error
	strings := make([]*uint16, len(Strings))

	for i, s := range Strings {
		strings[i], err = windows.UTF16PtrFromString(s)
		if err != nil {
			return err
		}
	}

	var rawData *uint8
	if len(RawData) == 0 {
		rawData = nil
	} else {
		rawData = &RawData[:1][0]
	}

	r1, _, lastErr := reportEvent.Call(
		uintptr(EventLog),
		uintptr(Type),
		uintptr(Category),
		uintptr(EventID),
		uintptr(0), // userSid
		uintptr(len(strings)),
		uintptr(len(RawData)),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(&strings[:1][0])),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(rawData)))
	// ReportEvent returns C FALSE (0) on error
	if r1 == 0 {
		return lastErr
	}

	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclearlog
func (api *API) EvtClearLog(ChannelPath string) error {
	channelPath, err := winutil.UTF16PtrOrNilFromString(ChannelPath)
	if err != nil {
		return err
	}

	r1, _, lastErr := evtClearLog.Call(
		uintptr(0), // local computer only
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(0), // TargetFilePath not supported
		uintptr(0)) // reserved must be 0
	// EvtClearLog returns C FALSE (0) on error
	if r1 == 0 {
		return lastErr
	}

	return nil
}
