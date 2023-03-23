// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"flag"
	"fmt"
	"testing"
	"time"

	pkglog "github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/bookmark"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"golang.org/x/sys/windows"
)

var debuglogFlag = flag.Bool("debuglog", false, "Enable seelog debug logging")

func optEnableDebugLogging() {
	// Enable logger
	if *debuglogFlag {
		pkglog.SetupLogger(seelog.Default, "debug")
	}
}

func TestInvalidChannel(t *testing.T) {
	optEnableDebugLogging()

	testerNames := eventlog_test.GetEnabledAPITesters()

	for _, tiName := range testerNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			ti := eventlog_test.GetAPITesterByName(tiName, t)
			sub := NewPullSubscription(
				"nonexistentchannel",
				"*",
				WithWindowsEventLogAPI(ti.API()))

			err := sub.Start()
			require.Error(t, err)
		})
	}
}

func createLog(t testing.TB, ti eventlog_test.APITester, channel string) error {
	err := ti.InstallChannel(channel)
	if !assert.NoError(t, err) {
		return err
	}
	err = ti.API().EvtClearLog(channel)
	if !assert.NoError(t, err) {
		return err
	}
	err = ti.InstallSource(channel, "testsource")
	if !assert.NoError(t, err) {
		return err
	}
	t.Cleanup(func() {
		ti.RemoveSource(channel, "testsource")
		ti.RemoveChannel(channel)
	})
	return nil
}

func startSubscription(t testing.TB, ti eventlog_test.APITester, channel string, options ...PullSubscriptionOption) (*PullSubscription, error) {
	opts := []PullSubscriptionOption{WithWindowsEventLogAPI(ti.API())}
	opts = append(opts, options...)

	// Create sub
	sub := NewPullSubscription(
		channel,
		"*",
		opts...)

	err := sub.Start()
	if !assert.NoError(t, err) {
		return nil, err
	}

	t.Cleanup(func() { sub.Stop() })
	return sub, nil
}

func getEventHandles(t testing.TB, ti eventlog_test.APITester, sub *PullSubscription, numEvents uint) ([]*EventRecord, error) {
	eventRecords, err := ReadNumEventsWithNotify(t, ti, sub, numEvents)
	if err != nil {
		return nil, err
	}
	count := uint(len(eventRecords))
	if !assert.Equal(t, numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents)) {
		return eventRecords, fmt.Errorf("Missing events")
	}
	return eventRecords, nil
}

func assertNoMoreEvents(t testing.TB, sub *PullSubscription) error {
	events, err := sub.GetEvents()
	if !assert.NoError(t, err, "Error should be nil when there are no more events") {
		return fmt.Errorf("Error should be nil when there are no more events")
	}
	if !assert.Nil(t, events, "[]events should be nil when there are no more events") {
		return fmt.Errorf("[]events should be nil when there are no more events")
	}
	return nil
}

func TestBenchmarkTestGetEventHandles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark tests with -short")
		return
	}
	optEnableDebugLogging()

	channel := "testchannel"
	numEvents := []uint{10, 100, 1000, 10000}

	testerNames := eventlog_test.GetEnabledAPITesters()

	for _, tiName := range testerNames {
		for _, v := range numEvents {
			t.Run(fmt.Sprintf("%vAPI/%d", tiName, v), func(t *testing.T) {
				ti := eventlog_test.GetAPITesterByName(tiName, t)
				createLog(t, ti, channel)
				err := ti.GenerateEvents(channel, v)
				require.NoError(t, err)
				result := testing.Benchmark(func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						sub, err := startSubscription(b, ti, channel, WithStartAtOldestRecord())
						require.NoError(b, err)
						_, err = getEventHandles(b, ti, sub, v)
						require.NoError(b, err)
						err = assertNoMoreEvents(b, sub)
						require.NoError(b, err)
						sub.Stop()
					}
				})
				total_events := float64(v) * float64(result.N)
				t.Logf("%.2f events/s (%.3fs)", total_events/result.T.Seconds(), result.T.Seconds())
			})
		}
	}
}

type GetEventsTestSuite struct {
	suite.Suite

	channelPath string
	testAPI     string
	numEvents   uint

	ti eventlog_test.APITester
}

func (s *GetEventsTestSuite) SetupSuite() {
	//fmt.Println("SetupSuite")

	optEnableDebugLogging()

	s.ti = eventlog_test.GetAPITesterByName(s.testAPI, s.T())
	err := s.ti.InstallChannel(s.channelPath)
	require.NoError(s.T(), err)
	err = s.ti.InstallSource(s.channelPath, "testsource")
	require.NoError(s.T(), err)
}

func (s *GetEventsTestSuite) TearDownSuite() {
	// fmt.Println("TearDownSuite")
	s.ti.RemoveSource(s.channelPath, "testsource")
	s.ti.RemoveChannel(s.channelPath)
}

func (s *GetEventsTestSuite) SetupTest() {
	// Ensure the log is empty
	// fmt.Println("SetupTest")
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)

}

func (s *GetEventsTestSuite) TearDownTest() {
	// fmt.Println("TearDownTest")
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
}

// Tests that the subscription can read old events (EvtSubscribeStartAtOldestRecord)
func (s *GetEventsTestSuite) TestReadOldEvents() {
	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Get Events
	_, err = getEventHandles(s.T(), s.ti, sub, 2*s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)
}

// Tests that the subscription is notified of and can read new events
func (s *GetEventsTestSuite) TestReadNewEvents() {
	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Eat the initial state
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Get Events
	_, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)
}

// Tests that the subscription can skip over old events (EvtSubscribeToFutureEvents)
func (s *GetEventsTestSuite) TestReadOnlyNewEvents() {
	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Get Events
	_, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)
}

// Tests that Stop() can be called when there are events available to be collected
func (s *GetEventsTestSuite) TestStopWhileWaitingWithEventsAvailable() {
	// Create subscription
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	readyToStop := make(chan struct{})
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read all events
		_, err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
		close(readyToStop)
		if !assert.NoError(s.T(), err) {
			return
		}
		// Purposefully don't call EvtNext the final time when it would normally return ERROR_NO_MORE_ITEMS.
		// This leaves the notify event set.
		// Wait for Stop() to finish
		<-stopped
		_, ok := <-sub.NotifyEventsAvailable
		assert.False(s.T(), ok, "Notify channel should be closed after Stop()")
	}()

	<-readyToStop
	sub.Stop()
	close(stopped)
	<-done
}

// Tests that Stop() can be called when the subscription is in a ERROR_NO_MORE_ITEMS state
func (s *GetEventsTestSuite) TestStopWhileWaitingNoMoreEvents() {
	// Create subscription
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	readyToStop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		// Read all events
		_, err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
		if err != nil {
			close(readyToStop)
			close(done)
			return
		}
		err = assertNoMoreEvents(s.T(), sub)
		if err != nil {
			close(readyToStop)
			close(done)
			return
		}
		close(readyToStop)
		// block on events available notification
		_, ok := <-sub.NotifyEventsAvailable
		assert.False(s.T(), ok, "Notify channel should be closed after Stop()")
		close(done)
	}()

	<-readyToStop
	sub.Stop()
	<-done
}

// Tests that GetEvents() still works when the NotifyEventsAvailable channel is ignored
func (s *GetEventsTestSuite) TestUnusedNotifyChannel() {
	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Loop so we test collecting old events and then new events
	for i := 0; i < 2; i++ {
		// Put events in the log
		err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
		require.NoError(s.T(), err)

		// Don't wait on the channel, just get events
		eventRecords, err := sub.GetEvents()
		require.NoError(s.T(), err)
		count := uint(len(eventRecords))
		require.Equal(s.T(), s.numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, s.numEvents))
		err = assertNoMoreEvents(s.T(), sub)
		require.NoError(s.T(), err)
	}
}

// Tests that GetEvents does not deadlock when notifyEventsAvailableLoop unexpectedly exits
func (s *GetEventsTestSuite) TestHandleEarlyNotifyLoopExit() {
	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// set stop event to trigger notify loop to exit
	windows.SetEvent(windows.Handle(sub.stopEventHandle))
	require.NoError(s.T(), err)

	// Eat the initial state
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// wait for the loop to exit
	sub.notifyEventsAvailableWaiter.Wait()

	// ensure the notify channel is closed
	_, ok := <-sub.NotifyEventsAvailable
	require.False(s.T(), ok, "Notify channel should be closed when notify loop exits")

	// Put events in the log
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// read all the events, don't wait on the (now closed) channel, just get events
	eventRecords, err := sub.GetEvents()
	require.NoError(s.T(), err)
	count := uint(len(eventRecords))
	require.Equal(s.T(), s.numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, s.numEvents))

	// trigger ERROR_NO_MORE_EVENTS, which triggers a sync with the (no longer running) notify loop
	events, err := sub.GetEvents()
	require.Nil(s.T(), events, "events should be nil on error")
	require.Error(s.T(), err, "GetEvents should return error when notify loop is no longer running")

	sub.Stop()

	// success if we did not deadlock
}

// Tests that NotifyEventsAvailable starts out set then becomes unset after calling GetEvents().
// This ensures the Windows Event Log API follows the behavior implied by the Microsoft example.
// https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events#pull-subscriptions
func (s *GetEventsTestSuite) TestChannelInitiallyNotified() {
	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// TODO: How to remove this sleep?
	time.Sleep(100 * time.Millisecond)

	select {
	case <-sub.NotifyEventsAvailable:
		break
	default:
		require.FailNow(s.T(), "NotifyEventsAvailable should not block the first time")
	}

	// should return empty
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// should block this time
	select {
	case <-sub.NotifyEventsAvailable:
		require.FailNow(s.T(), "NotifyEventsAvailable should block if no events available")
	default:
		break
	}
}

// Tests that the subscription can start from a provided bookmark
func (s *GetEventsTestSuite) TestStartAfterBookmark() {
	//
	// Add some events to the log and create a bookmark
	//

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create bookmark
	bookmark, err := evtbookmark.New(evtbookmark.WithWindowsEventLogAPI(s.ti.API()))
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Update bookmark to last event
	// Must do so before closing the subscription
	bookmark.Update(events[len(events)-1].EventRecordHandle)

	// Close out this subscription
	sub.Stop()

	//
	// Add more events and verify the log contains twice as many events
	//

	// Add some more events
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err = startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err = getEventHandles(s.T(), s.ti, sub, 2*s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Close out this subscription
	sub.Stop()

	//
	// Start subscription part way through log with bookmark
	//

	// Create a new subscription starting from the bookmark
	sub, err = startSubscription(s.T(), s.ti, s.channelPath, WithStartAfterBookmark(bookmark))
	require.NoError(s.T(), err)

	// Get Events
	_, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	// Since we started halfway through there should be no more events
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)
}

// Tests that the subscription starts when a bookmark is not found and the EvtSubscribeStrict flag is NOT provided
func (s *GetEventsTestSuite) TestStartAfterBookmarkNotFoundWithoutStrictFlag() {
	//
	// Add some events to the log and create a bookmark
	//

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create bookmark
	bookmark, err := evtbookmark.New(evtbookmark.WithWindowsEventLogAPI(s.ti.API()))
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Update bookmark to last event
	// Must do so before closing the subscription
	bookmark.Update(events[len(events)-1].EventRecordHandle)

	// Close out this subscription
	sub.Stop()

	// Clear the log so the bookmark is missing
	err = s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)

	//
	// Add more events and verify the log contains only that many events
	//

	// Add some more events
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err = startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Close out this subscription
	sub.Stop()

	//
	// Bookmark is not found so subscription should start from beginning
	//

	// Create a new subscription starting from the bookmark
	sub, err = startSubscription(s.T(), s.ti, s.channelPath, WithStartAfterBookmark(bookmark))
	// strict flag not set so there should be no error
	require.NoError(s.T(), err)

	// Get Events
	_, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)
}

// Tests that the subscription returns an error when a bookmark is not found and the EvtSubscribeStrict flag is provided
func (s *GetEventsTestSuite) TestStartAfterBookmarkNotFoundWithStrictFlag() {
	//
	// Add some events to the log and create a bookmark
	//

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create bookmark
	bookmark, err := evtbookmark.New(evtbookmark.WithWindowsEventLogAPI(s.ti.API()))
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Update bookmark to last event
	// Must do so before closing the subscription
	bookmark.Update(events[len(events)-1].EventRecordHandle)

	// Close out this subscription
	sub.Stop()

	// Clear the log so the bookmark is missing
	err = s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)

	//
	// Add more events and verify the log contains only that many events
	//

	// Add some more events
	err = s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err = startSubscription(s.T(), s.ti, s.channelPath, WithStartAtOldestRecord())
	require.NoError(s.T(), err)

	// Read the events
	events, err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// Close out this subscription
	sub.Stop()

	//
	// With bookmark not found and strict flag set subscription should fail
	//

	sub = NewPullSubscription(
		s.channelPath,
		"*",
		WithWindowsEventLogAPI(s.ti.API()),
		WithStartAfterBookmark(bookmark),
		WithSubscribeFlags(evtapi.EvtSubscribeStrict))
	err = sub.Start()
	require.Error(s.T(), err, "Subscription should return error when bookmark is not found and the Strict flag is set")
}

func TestLaunchGetEventsTestSuite(t *testing.T) {
	testerNames := eventlog_test.GetEnabledAPITesters()

	for _, tiName := range testerNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			var s GetEventsTestSuite
			s.channelPath = "testchannel"
			s.testAPI = tiName
			s.numEvents = 10
			suite.Run(t, &s)
		})
	}
}
