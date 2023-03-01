// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows
// +build windows

package windowsevent

/*
#cgo LDFLAGS: -l wevtapi
#include "event.h"
*/
import "C"

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog"
	evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	winevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
)

// Start starts tailing the event log.
func (t *Tailer) Start() {
	log.Infof("Starting windows event log tailing for channel %s query %s", t.config.ChannelPath, t.config.Query)
	go t.tail()
}

// Stop stops the tailer
func (t *Tailer) Stop() {
	log.Info("Stop tailing windows event log")
	t.sub.Stop()
	t.stop <- struct{}{}
	<-t.done
}

// tail subscribes to the channel for the windows events
func (t *Tailer) tail() {
	t.context = &eventContext{
		id: indexForTailer(t),
	}
	if t.evtapi == nil {
		t.evtapi = winevtapi.NewWindowsEventLogAPI()
	}
	t.sub = eventlog.NewPullSubscription(
		t.config.ChannelPath,
		t.config.Query,
		eventlog.WithEventLoopWaitMs(50),
		eventlog.WithWindowsEventLogAPI(t.evtapi))
	err := t.sub.Start()
	if err != nil {
		err = fmt.Errorf("Failed to start subscription: %v", err)
		log.Errorf("%v", err)
		t.source.Status.Error(err)
		return
	}
	t.source.Status.Success()

	// wait for stop signal
	eventLoop:
		for {
			select {
			case <-t.stop:
				break eventLoop
			case _, ok := <-t.sub.NotifyEventsAvailable:
				if !ok {
					break eventLoop
				}
				// events are available, read them
				for {
					events, err := t.sub.GetEvents()
					if err != nil {
						// error
						log.Errorf("GetEvents failed: %v", err)
						break eventLoop
					}
					if events == nil {
						// no more events
						log.Debugf("No more events")
						break
					}
					for _,eventRecord := range events {
						goNotificationCallback(t.evtapi, eventRecord.EventRecordHandle, C.PVOID(uintptr(unsafe.Pointer(t.context))))
					}
				}
			}
		}
	t.done <- struct{}{}
	return
}

func goNotificationCallback(evtapi evtapidef.IWindowsEventLogAPI, eventRecordHandle evtapidef.EventRecordHandle, ctx C.PVOID) {
	goctx := *(*eventContext)(unsafe.Pointer(uintptr(ctx)))
	log.Debug("Callback from ", goctx.id)

	xmlData, err := evtapi.EvtRenderEventXml(eventRecordHandle)
	if err != nil {
		log.Warnf("Error rendering xml: %v", err)
		return
	}
	xml := windows.UTF16ToString(xmlData)

	richEvt := &richEvent{
		xmlEvent: xml,
		message:  "",
		task:     "",
		opcode:   "",
		level:    "",
	}

	t, exists := tailerForIndex(goctx.id)
	if !exists {
		log.Warnf("Got invalid eventContext id %d when map is %v", goctx.id, eventContextToTailerMap)
		return
	}
	msg, err := t.toMessage(richEvt)
	if err != nil {
		log.Warnf("Couldn't convert xml to json: %s for event %s", err, richEvt.xmlEvent)
		return
	}

	t.source.RecordBytes(int64(len(msg.Content)))
	t.outputChan <- msg
}

var (
	modWinEvtAPI = windows.NewLazyDLL("wevtapi.dll")

	procEvtRender = modWinEvtAPI.NewProc("EvtRender")
)


type evtSubscribeNotifyAction int32
type evtSubscribeFlags int32

const (
	EvtSubscribeActionError   evtSubscribeNotifyAction = 0
	EvtSubscribeActionDeliver evtSubscribeNotifyAction = 1

	EvtSubscribeOriginMask          evtSubscribeFlags = 0x3
	EvtSubscribeTolerateQueryErrors evtSubscribeFlags = 0x1000
	EvtSubscribeStrict              evtSubscribeFlags = 0x10000

	EvtRenderEventValues = 0 // Variants
	EvtRenderEventXml    = 1 // XML
	EvtRenderBookmark    = 2 // Bookmark

	maxRunes      = 1<<17 - 1 // 128 kB
	truncatedFlag = "...TRUNCATED..."
)

type EVT_SUBSCRIBE_FLAGS int

const (
	_ = iota
	EvtSubscribeToFutureEvents
	EvtSubscribeStartAtOldestRecord
	EvtSubscribeStartAfterBookmark
)

// LPWSTRToString converts a C.LPWSTR to a string. It also truncates the
// strings to 128kB as a basic protection mechanism to avoid allocating an
// array too big. Messages with more than 128kB are likely to be bigger
// than 256kB when serialized and then dropped
func LPWSTRToString(cwstr C.LPWSTR) string {
	ptr := unsafe.Pointer(cwstr)
	sz := C.wcslen((*C.wchar_t)(ptr))
	sz = min(sz, maxRunes)
	wstr := (*[maxRunes]uint16)(ptr)[:sz:sz]
	return string(utf16.Decode(wstr))
}

func min(x, y C.size_t) C.size_t {
	if x > y {
		return y
	}
	return x
}
