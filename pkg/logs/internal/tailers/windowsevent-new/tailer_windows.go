// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows
// +build windows

package windowsevent

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/subscription"
)

const (
	maxRunes      = 1<<17 - 1 // 128 kB
	truncatedFlag = "...TRUNCATED..."
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
	if t.evtapi == nil {
		t.evtapi = winevtapi.New()
	}
	// subscription
	t.sub = evtsubscribe.NewPullSubscription(
		t.config.ChannelPath,
		t.config.Query,
		evtsubscribe.WithWindowsEventLogAPI(t.evtapi))
	err := t.sub.Start()
	if err != nil {
		err = fmt.Errorf("Failed to start subscription: %v", err)
		log.Errorf("%v", err)
		t.source.Status.Error(err)
		return
	}

	// render context for system values
	t.systemRenderContext, err = t.evtapi.EvtCreateRenderContext(nil, evtapi.EvtRenderContextSystem)
	if err != nil {
		err = fmt.Errorf("Failed to create system render context: %v", err)
		log.Errorf("%v", err)
		t.source.Status.Error(err)
		return
	}
	defer evtapi.EvtCloseRenderContext(t.evtapi, t.systemRenderContext)

	t.source.Status.Success()

	// wait for stop signal
	t.eventLoop()
	t.done <- struct{}{}
	return
}

func (t *Tailer) eventLoop() {
	for {
		select {
		case <-t.stop:
			return
		case _, ok := <-t.sub.NotifyEventsAvailable:
			if !ok {
				return
			}
			// events are available, read them
			for {
				events, err := t.sub.GetEvents()
				if err != nil {
					// error
					log.Errorf("GetEvents failed: %v", err)
					return
				}
				if events == nil {
					// no more events
					log.Debugf("No more events")
					break
				}
				for _,eventRecord := range events {
					t.handleEvent(eventRecord.EventRecordHandle)
					evtapi.EvtCloseRecord(t.evtapi, eventRecord.EventRecordHandle)
				}
			}
		}
	}
}

func (t *Tailer) handleEvent(eventRecordHandle evtapi.EventRecordHandle) {

	richEvt := t.enrichEvent(eventRecordHandle)

	msg, err := t.toMessage(richEvt)
	if err != nil {
		log.Warnf("Couldn't convert xml to json: %s for event %s", err, richEvt.xmlEvent)
		return
	}

	t.source.RecordBytes(int64(len(msg.Content)))
	t.outputChan <- msg
}

// enrichEvent renders data, and set the rendered fields to the richEvent.
// We need this some fields in the Windows Events are coded with numerical
// value. We then call a function in the Windows API that match the code to
// a human readable value.
func (t *Tailer) enrichEvent(event evtapi.EventRecordHandle) *richEvent {
	xmlData, err := t.evtapi.EvtRenderEventXml(event)
	if err != nil {
		log.Warnf("Error rendering xml: %v", err)
		return nil
	}
	xml := windows.UTF16ToString(xmlData)
	log.Debug(xml)

	vals, err := t.evtapi.EvtRenderEventValues(t.systemRenderContext, event)
	if err != nil {
		log.Warnf("Error rendering event values: %v", err)
		return nil
	}

	providerName, err := vals.String(evtapi.EvtSystemProviderName)
	if err != nil {
		log.Warnf("Failed to get provider name: %v", err)
		return nil
	}

	pm, err := t.evtapi.EvtOpenPublisherMetadata(providerName, "")
	if err != nil {
		log.Warnf("Failed to get publisher metadata for provider '%s': %v", providerName, err)
		return nil
	}

	var message, task, opcode, level string

	message, _ = t.evtapi.EvtFormatMessage(pm, event, 0, nil, evtapi.EvtFormatMessageEvent)
	task, _ = t.evtapi.EvtFormatMessage(pm, event, 0, nil, evtapi.EvtFormatMessageTask)
	opcode, _ = t.evtapi.EvtFormatMessage(pm, event, 0, nil, evtapi.EvtFormatMessageOpcode)
	level, _ = t.evtapi.EvtFormatMessage(pm, event, 0, nil, evtapi.EvtFormatMessageLevel)

	// Truncates the message. Messages with more than 128kB are likely to be bigger
	// than 256kB when serialized and then dropped
	if len(message) >= maxRunes {
		message = message + truncatedFlag
	}

	return &richEvent{
		xmlEvent: xml,
		message:  message,
		task:     task,
		opcode:   opcode,
		level:    level,
	}
}
