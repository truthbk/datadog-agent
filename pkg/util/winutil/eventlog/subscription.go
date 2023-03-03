// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"fmt"
	"sync"

	// "github.com/DataDog/datadog-agent/comp/core/log"
	pkglog "github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"golang.org/x/sys/windows"
)

const (
	// How many events to fetch per EvtNext call
	DEFAULT_EVENT_BATCH_COUNT = 512
)

type PullSubscription struct {
	// Configuration
	ChannelPath string
	Query string
	EventBatchCount uint

	// Notify user that event records are available
	NotifyEventsAvailable chan struct{}

	// datadog components
	//log log.Component

	// Windows API
	eventLogAPI evtapi.API
	subscriptionHandle evtapi.EventResultSetHandle
	waitEventHandle evtapi.WaitEventHandle
	stopEventHandle evtapi.WaitEventHandle
	evtNextStorage []evtapi.EventRecordHandle

	// Query loop management
	started bool
	notifyEventsAvailableWaiter sync.WaitGroup
	notifyStop chan struct{}

	// notifyNoMoreItems synchronizes notifyEventsAvailableLoop and GetEvents when
	// EvtNext returns ERROR_NO_MORE_ITEMS.
	// GetEvents writes to this channel to tell notifyEventsAvailableLoop to skip writing
	// to the NotifyEventsAvailable channel and return to the WaitForMultipleObjects call.
	// Without this synchronization notifyEventsAvailableLoop would block writing to the
	// NotifyEventsAvailable channel until the user read from the channel again, at which
	// point the user would be erroneously notified that events are available.
	notifyNoMoreItems chan struct{}
	notifyNoMoreItemsComplete chan struct{}
}

type EventRecord struct {
	EventRecordHandle evtapi.EventRecordHandle
}

func newSubscriptionWaitEvent() (evtapi.WaitEventHandle, error) {
	// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
	// Manual reset, must be initally set, Windows will not set it for old events
	hEvent, err := windows.CreateEvent(nil, 1, 1, nil)
	return evtapi.WaitEventHandle(hEvent), err
}

func newStopWaitEvent() (evtapi.WaitEventHandle, error) {
	// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
	// Manual reset, initally unset
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	return evtapi.WaitEventHandle(hEvent), err
}

//func NewPullSubscription(log log.Component) *PullSubscription {
func NewPullSubscription(ChannelPath, Query string, options ...func(*PullSubscription)) *PullSubscription {
	var q PullSubscription
	q.subscriptionHandle = evtapi.EventResultSetHandle(0)
	q.waitEventHandle = evtapi.WaitEventHandle(0)

	q.EventBatchCount = DEFAULT_EVENT_BATCH_COUNT

	q.ChannelPath = ChannelPath
	q.Query = Query
	// q.log = log

	for _, o := range options {
		o(&q)
	}

	return &q
}

func WithEventBatchCount(count uint) func(*PullSubscription) {
   return func (q *PullSubscription) {
       q.EventBatchCount = count
   }
}

func WithWindowsEventLogAPI(api evtapi.API) func(*PullSubscription) {
	return func (q *PullSubscription) {
		q.eventLogAPI = api
	}
}

func (q *PullSubscription) Start() (error) {

	if q.started {
		return fmt.Errorf("Query subscription is already started")
	}

	// create subscription
	hSubWait, err := newSubscriptionWaitEvent()
	if err != nil {
		return err
	}
	hSub, err := q.eventLogAPI.EvtSubscribe(
		hSubWait,
		q.ChannelPath,
		q.Query,
		evtapi.EventBookmarkHandle(0),
		evtapi.EvtSubscribeStartAtOldestRecord)
	if err != nil {
		safeCloseNullHandle(windows.Handle(hSubWait))
		return err
	}

	hStopWait, err := newStopWaitEvent()
	if err != nil {
		return err
	}

	// alloc reusable storage for EvtNext output
	q.evtNextStorage = make([]evtapi.EventRecordHandle, q.EventBatchCount)

	// Query loop management
	q.notifyStop = make(chan struct{})
	q.notifyNoMoreItems = make(chan struct{})
	q.notifyNoMoreItemsComplete = make(chan struct{})
	q.NotifyEventsAvailable = make(chan struct{})
	q.waitEventHandle = hSubWait
	q.stopEventHandle = hStopWait
	q.subscriptionHandle = hSub

	// start goroutine to query events for channel
	q.notifyEventsAvailableWaiter.Add(1)
	go q.notifyEventsAvailableLoop()
	q.started = true

	return nil
}

func (q *PullSubscription) Stop() {
	if !q.started {
		return
	}

	// Wait for notifyEventsAvailableLoop to stop
	windows.SetEvent(windows.Handle(q.stopEventHandle))
	close(q.notifyStop)
	q.notifyEventsAvailableWaiter.Wait()

	close(q.notifyNoMoreItems)
	close(q.notifyNoMoreItemsComplete)

	// Cleanup Windows API
	evtapi.EvtCloseResultSet(q.eventLogAPI, q.subscriptionHandle)
	safeCloseNullHandle(windows.Handle(q.waitEventHandle))
	safeCloseNullHandle(windows.Handle(q.stopEventHandle))

	q.started = false
}

// notifyEventsAvailableLoop writes to the NotifyEventsAvailable channel
// when the Windows Event Log API Subscription sets the waitEventHandle.
// On return, closes the NotifyEventsAvailable channel to notify the user
// of an error or a Stop().
func (q *PullSubscription) notifyEventsAvailableLoop() {
	// q.Stop() waits on this goroutine to finish, notify it that we are done
	defer q.notifyEventsAvailableWaiter.Done()
	// close the notify channel so the user knows this loop is dead
	defer close(q.NotifyEventsAvailable)

	waiters := []windows.Handle{windows.Handle(q.waitEventHandle), windows.Handle(q.stopEventHandle)}

	for {
		dwWait, err := windows.WaitForMultipleObjects(waiters, false, windows.INFINITE)
		if err != nil {
			// WAIT_FAILED
			pkglog.Errorf("WaitForMultipleObjects failed: %", err)
			return
		}
		if dwWait == windows.WAIT_OBJECT_0 {
			// Event records are available, notify the user
			pkglog.Debugf("Events are available")
			select {
				case <- q.notifyStop:
					return
				case q.NotifyEventsAvailable <- struct{}{}:
					break
				case <- q.notifyNoMoreItems:
					// EvtNext called, there are no more items to read, this case
					// allows us to cancel sending NotifyEventsAvailable to the user.
					// Now we must wait for the event to be reset to ensure WaitForMultipleObjects will
					// block until Windows sets the event again.
					// We cannot just call ResetEvent here instead because that creates a race
					// with the SetEvent call in GetEvents() that could create a deadlock.
					<-q.notifyNoMoreItemsComplete
					break
			}
		} else if dwWait == (windows.WAIT_OBJECT_0+1) {
			// Stop event is set
			return
		} else if dwWait == uint32(windows.WAIT_TIMEOUT) {
			// timeout
			// this shouldn't happen
			pkglog.Errorf("WaitForMultipleObjects timed out")
			return
		} else {
			// some other error occurred
			gle := windows.GetLastError()
			pkglog.Errorf("WaitForMultipleObjects unknown error: wait(%d,%#x) gle(%d,%#x)",
				dwWait,
				dwWait,
				gle,
				gle)
			return
		}
	}
}

// synchronizeNoMoreItems is used to synchronize notifyEventsAvailableLoop when
// EvtNext returns ERROR_NO_MORE_ITEMS.
// Note that the Microsoft's Pull Subscriptions model is inherently racey. It is possible
// for EvtNext to return ERROR_NO_MORE_ITEMS and then for Windows to call SetEvent(waitHandle)
// before our code reaches the ResetEvent(waitHandle). If this happens we will not see those
// events until newer events are created and Windows once again calls SetEvent(waitHandle).
func (q *PullSubscription) synchronizeNoMoreItems() error {
	// If notifyEventsAvailableLoop is blocking on WaitForMultipleObjects
	// wake it up so we can sync on notifyNoMoreItems
	// If notifyEventsAvailableLoop is blocking on notifyNoMoreItems then this is a no-op
	windows.SetEvent(windows.Handle(q.waitEventHandle))
	// windows.ResetEvent(windows.Handle(q.waitEventHandle))
	// If notifyEventsAvailableLoop is blocking on sending NotifyEventsAvailable
	// then wake/cancel it so it does not erroneously send NotifyEventsAvailable.
	select {
		case <- q.notifyStop:
			return fmt.Errorf("stop signal")
		case q.notifyNoMoreItems <- struct{}{}:
			break
	}
	// Reset the events ready event so notifyEventsAvailableLoop will wait again in WaitForMultipleObjects,
	// then write to notifyNoMoreItemsComplete to tell the loop that the event has been reset and it
	// can safely continue.
	windows.ResetEvent(windows.Handle(q.waitEventHandle))
	q.notifyNoMoreItemsComplete <- struct{}{}
	return nil
}

// GetEvents returns the next available events in the subscription.
func (q *PullSubscription) GetEvents() ([]*EventRecord, error) {

	// TODO: should we use infinite or a small value?
	//       it shouldn't block or timeout because we had out event set?
	eventRecordHandles, err := q.eventLogAPI.EvtNext(q.subscriptionHandle, q.evtNextStorage, uint(len(q.evtNextStorage)), windows.INFINITE)
	if err == nil {
		pkglog.Debugf("EvtNext returned %v handles", len(eventRecordHandles))
		// got events
		eventRecords := q.parseEventRecordHandles(eventRecordHandles)
		return eventRecords, nil
	} else if err == windows.ERROR_TIMEOUT {
		// no more events
		// TODO: Should we reset the handle? MS example says no
		pkglog.Errorf("evtnext timeout")
		return nil, fmt.Errorf("timeout")
	} else if err == windows.ERROR_NO_MORE_ITEMS {
		// no more events
		pkglog.Debugf("EvtNext returned no more items")
		err := q.synchronizeNoMoreItems()
		if err != nil {
			return nil, err
		}
		// not an error, there are just no more items
		return nil, nil
	} else {
		pkglog.Errorf("EvtNext failed: %v", err)
		return nil, err
	}

	return nil, nil
}

func (q *PullSubscription) parseEventRecordHandles(eventRecordHandles []evtapi.EventRecordHandle) []*EventRecord {
	var err error

	eventRecords := make([]*EventRecord, len(eventRecordHandles))

	for i, eventRecordHandle := range eventRecordHandles {
		eventRecords[i], err = q.parseEventRecordHandle(eventRecordHandle)
		if err != nil {
			pkglog.Errorf("Failed to process event (%#x): %v", eventRecordHandle, err)
		}
	}

	return eventRecords
}

func (q *PullSubscription) parseEventRecordHandle(eventRecordHandle evtapi.EventRecordHandle) (*EventRecord, error) {
	var e EventRecord
	e.EventRecordHandle = eventRecordHandle
	// TODO: Render?
	return &e, nil
}

func safeCloseNullHandle(h windows.Handle) {
	if h != windows.Handle(0) {
		windows.CloseHandle(h)
	}
}

