// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"fmt"
	"unsafe"

    "github.com/DataDog/datadog-agent/pkg/util/winutil"

	"golang.org/x/sys/windows"
)

var (
	wevtapi = windows.NewLazySystemDLL("wevtapi.dll")
	evtSubscribe = wevtapi.NewProc("EvtSubscribe")
	evtClose = wevtapi.NewProc("EvtClose")
	evtNext = wevtapi.NewProc("EvtNext")
	evtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	evtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
	evtCreateRenderContext = wevtapi.NewProc("EvtCreateRenderContext")
	evtRender = wevtapi.NewProc("EvtRender")
)

const (
	// EVT_SUBSCRIBE_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags
    EvtSubscribeToFutureEvents = iota + 1
    EvtSubscribeStartAtOldestRecord
    EvtSubscribeStartAfterBookmark
    EvtSubscribeOriginMask
    EvtSubscribeTolerateQueryErrors = 0x1000
    EvtSubscribeStrict = 0x10000
)

const (
	// EVT_RENDER_CONTEXT_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_render_context_flags
	EvtRenderContextValues = iota
	EvtRenderContextSystem
	EvtRenderContextUser
)

const (
	// EVT_RENDER_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_render_flags
	EvtRenderEventValues = iota
	EvtRenderEventXml
	EvtRenderBookmark
)

// Returned from EvtQuery and EvtSubscribe
type EventResultSetHandle windows.Handle

// Returned from EvtNext
type EventRecordHandle windows.Handle

// Returned from EvtCreateBookmark
type EventBookmarkHandle windows.Handle

// Returned from EvtCreateRenderContext
type EventRenderContextHandle windows.Handle

// Returned from CreateEvent
type WaitEventHandle windows.Handle

type EventFragmentHandle interface {
	EventRecordHandle | EventBookmarkHandle
}

// Pass returned handle to EvtClose
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
func EvtSubscribe(
	SignalEvent WaitEventHandle,
	ChannelPath string,
	Query string,
	Bookmark EventBookmarkHandle,
	Flags uint) (EventResultSetHandle, error) {

	// Convert Go string to Windows API string
	channelPath, err := winutil.UTF16PtrOrNilFromString(ChannelPath)
	if err != nil {
		return EventResultSetHandle(0), err
	}
	query, err := winutil.UTF16PtrOrNilFromString(Query)
	if err != nil {
		return EventResultSetHandle(0), err
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

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose
func EvtClose(h windows.Handle) {
	if h != windows.Handle(0) {
		evtClose.Call(uintptr(h))
	}
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreatebookmark
func EvtCreateBookmark(BookmarkXml string) (EventBookmarkHandle, error) {
	var bookmarkXml *uint16

	bookmarkXml, err := winutil.UTF16PtrOrNilFromString(BookmarkXml)
	if err != nil {
		return EventBookmarkHandle(0), err
	}

	r1, _, lastErr := evtCreateBookmark.Call(uintptr(unsafe.Pointer(bookmarkXml)))
	// EvtCreateBookmark returns NULL on error
	if r1 == 0 {
		return EventBookmarkHandle(0), lastErr
	}

	return EventBookmarkHandle(r1), nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtupdatebookmark
func EvtUpdateBookmark(Bookmark EventBookmarkHandle, Event EventRecordHandle) error {
	r1, _, lastErr := evtUpdateBookmark.Call(uintptr(Bookmark), uintptr(Event))
	// EvtUpdateBookmark returns C FALSE (0) on error
	if r1 == 0 {
		return lastErr
	}

	return nil
}

// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreaterendercontext
func EvtCreateRenderContext(ValuePaths []string, Flags uint) (EventRenderContextHandle, error) {
	var err error
	valuePaths := make([]*uint16, len(ValuePaths))

	for i, v := range ValuePaths {
		valuePaths[i], err = windows.UTF16PtrFromString(v)
		if err != nil {
			return EventRenderContextHandle(0), err
		}
	}

	r1, _, lastErr := evtCreateRenderContext.Call(
		uintptr(len(valuePaths)),
		// TODO: use unsafe.SliceData in go1.20
		uintptr(unsafe.Pointer(&valuePaths[:1][0])),
		uintptr(Flags))
	// EvtCreateRenderContext returns NULL on error
	if r1 == 0 {
		return EventRenderContextHandle(0), lastErr
	}

	return EventRenderContextHandle(r1), nil
}

// EvtRenderText supports the EvtRenderEventXml and EvtRenderBookmark Flags
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
func EvtRenderText[FragmentType EventFragmentHandle](
	Fragment FragmentType,
	Flags uint) ([]uint16, error) {

	if Flags != EvtRenderEventXml && Flags != EvtRenderBookmark {
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

//
// Helpful wrappers for custom types
//
func EvtCloseResultSet(h EventResultSetHandle) {
	EvtClose(windows.Handle(h))
}

func EvtCloseBookmark(h EventBookmarkHandle) {
	EvtClose(windows.Handle(h))
}

func EvtCloseRecord(h EventRecordHandle) {
	EvtClose(windows.Handle(h))
}

func safeCloseNullHandle(h windows.Handle) {
	if h != windows.Handle(0) {
		windows.CloseHandle(h)
	}
}

