// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"fmt"
	"testing"
	"time"

	"github.com/cihub/seelog"
	pkglog "github.com/DataDog/datadog-agent/pkg/util/log"

    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)


func TestInvalidChannel(t *testing.T) {
	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	for _, tiName := range testInterfaceNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			ti := eventlog_test.GetTestInterfaceByName(tiName, t)
			sub := NewPullSubscription(
				"nonexistentchannel",
				"*",
				WithWindowsEventLogAPI(ti.EventLogAPI()))

			err := sub.Start()
			require.Error(t, err)
		})
	}
}

func createLog(t testing.TB, ti eventlog_test.EventLogTestInterface, channel string) {
	err := ti.InstallChannel(channel)
	require.NoError(t, err)
	err = ti.EventLogAPI().EvtClearLog(channel)
	require.NoError(t, err)
	err = ti.InstallSource(channel, "testsource")
	require.NoError(t, err)
	t.Cleanup(func() {
		ti.RemoveSource(channel, "testsource")
		ti.RemoveChannel(channel)
	})
}

func startSubscription(t testing.TB, ti eventlog_test.EventLogTestInterface, channel string) *PullSubscription {
	// Create sub
	sub := NewPullSubscription(
		channel,
		"*",
		WithWindowsEventLogAPI(ti.EventLogAPI()))

	err := sub.Start()
	require.NoError(t, err)

	t.Cleanup(func() { sub.Stop() })
	return sub
}

func getEventHandles(t testing.TB, ti eventlog_test.EventLogTestInterface, sub *PullSubscription, numEvents uint) {
	eventRecords := ReadNumEventsWithNotify(t, ti, sub, numEvents)
	count := uint(len(eventRecords))
	require.Equal(t, numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents))
}

func requireNoMoreEvents(t testing.TB, sub *PullSubscription) {
	events, err := sub.GetEvents()
	require.NoError(t, err, "Error should be nil when there are no more events")
	require.Nil(t, events, "[]events should be nil when there are no more events")
}

func TestBenchmarkTestGetEventHandles(t *testing.T) {
	if testing.Short() {
		return
	}

	channel := "testchannel"
	numEvents := []uint{10,100,1000,10000}

	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	for _, tiName := range testInterfaceNames {
		for _, v := range numEvents {
			t.Run(fmt.Sprintf("%vAPI/%d", tiName, v), func(t *testing.T) {
				ti := eventlog_test.GetTestInterfaceByName(tiName, t)
				createLog(t, ti, channel)
				err := ti.GenerateEvents(channel, v)
				require.NoError(t, err)
				result := testing.Benchmark(func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						sub := startSubscription(b, ti, channel)
						getEventHandles(b, ti, sub, v)
						requireNoMoreEvents(b, sub)
						sub.Stop()
					}
				})
				total_events := float64(v)*float64(result.N)
				t.Logf("%.2f events/s (%.3fs)", total_events/result.T.Seconds(), result.T.Seconds())
			})
		}
	}
}

type GetEventsTestSuite struct {
	suite.Suite

	channelPath string
	testAPI string
	numEvents uint

	ti eventlog_test.EventLogTestInterface
}

func (s *GetEventsTestSuite) SetupSuite() {
	// Enable logger
	pkglog.SetupLogger(seelog.Default, "debug")
	fmt.Println("SetupSuite")

	s.ti = eventlog_test.GetTestInterfaceByName(s.testAPI, s.T())
	err := s.ti.InstallChannel(s.channelPath)
	require.NoError(s.T(), err)
	err = s.ti.InstallSource(s.channelPath, "testsource")
	require.NoError(s.T(), err)
}

func (s *GetEventsTestSuite) TearDownSuite() {
	fmt.Println("TearDownSuite")
	s.ti.RemoveSource(s.channelPath, "testsource")
	s.ti.RemoveChannel(s.channelPath)
}

func (s *GetEventsTestSuite) SetupTest() {
	// Ensure the log is empty
	fmt.Println("SetupTest")
	err := s.ti.EventLogAPI().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)

}

func (s *GetEventsTestSuite) TearDownTest() {
	fmt.Println("SetupTest")
	err := s.ti.EventLogAPI().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
}

func (s *GetEventsTestSuite) TestReadOldEvents() {
	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Get Events
	getEventHandles(s.T(), s.ti, sub, s.numEvents)
}

func (s *GetEventsTestSuite) TestReadNewEvents() {
	// Create sub
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Eat the initial state
	requireNoMoreEvents(s.T(), sub)

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Get Events
	getEventHandles(s.T(), s.ti, sub, s.numEvents)
	requireNoMoreEvents(s.T(), sub)
}

// Tests that Stop() can be called when there are events available to be collected
func (s *GetEventsTestSuite) TestStopWhileWaitingWithEventsAvailable() {
	// Create subscription
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	readyToStop := make(chan struct{})
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		// Read all events
		getEventHandles(s.T(), s.ti, sub, s.numEvents)
		close(readyToStop)
		// Purposefully don't call EvtNext the final time when it would normally return ERROR_NO_MORE_ITEMS.
		// This leaves the notify event set.
		// Wait for Stop() to finish
		<-stopped
		_, ok := <- sub.NotifyEventsAvailable
		require.False(s.T(), ok, "Notify channel should be closed after Stop()")
		close(done)
	}()

	<-readyToStop
	sub.Stop()
	close(stopped)
	<-done
}

// Tests that Stop() can be called when the subscription is in a ERROR_NO_MORE_ITEMS state
func (s *GetEventsTestSuite) TestStopWhileWaitingNoMoreEvents() {
	// Create subscription
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	readyToStop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		// Read all events
		getEventHandles(s.T(), s.ti, sub, s.numEvents)
		requireNoMoreEvents(s.T(), sub)
		close(readyToStop)
		// block on events available notification
		_, ok := <- sub.NotifyEventsAvailable
		require.False(s.T(), ok, "Notify channel should be closed after Stop()")
		close(done)
	}()

	<-readyToStop
	sub.Stop()
	<-done
}

// Tests that GetEvents() still works when the NotifyEventsAvailable channel is ignored
func (s *GetEventsTestSuite) TestUnusedNotifyChannel() {
	// Create sub
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Loop so we test collecting old events and then new events
	for i := 0; i < 2; i++ {
		// Put events in the log
		err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
		require.NoError(s.T(), err)

		// Don't wait on the channel, just get events
		eventRecords, err := sub.GetEvents()
		count := uint(len(eventRecords))
		require.Equal(s.T(), s.numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, s.numEvents))
		requireNoMoreEvents(s.T(), sub)
	}
}

// Tests that NotifyEventsAvailable starts out set then becomes unset after calling GetEvents().
// This ensures the Windows Event Log API follows the behavior implied by the Microsoft example.
// https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events#pull-subscriptions
func (s *GetEventsTestSuite) TestChannelInitiallyNotified() {
	// Create sub
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// TODO: How to remove this sleep?
	time.Sleep(100*time.Millisecond)

	select {
	case <- sub.NotifyEventsAvailable:
		break
	default:
		require.FailNow(s.T(), "NotifyEventsAvailable should not block the first time")
	}

	// should return empty
	requireNoMoreEvents(s.T(), sub)

	// should block this time
	select {
	case <- sub.NotifyEventsAvailable:
		require.FailNow(s.T(), "NotifyEventsAvailable should block if no events available")
	default:
		break
	}
}

func TestLaunchGetEventsTestSuite(t *testing.T) {
	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	for _, tiName := range testInterfaceNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			var s GetEventsTestSuite
			s.channelPath = "testchannel"
			s.testAPI = tiName
			s.numEvents = 10
			suite.Run(t, &s)
		})
	}
}
