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

	// "github.com/cihub/seelog"
	// pkglog "github.com/DataDog/datadog-agent/pkg/util/log"

    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestInvalidChannel(t *testing.T) {
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

func startSubscription(t testing.TB, ti eventlog_test.APITester, channel string) (*PullSubscription, error) {
	// Create sub
	sub := NewPullSubscription(
		channel,
		"*",
		WithWindowsEventLogAPI(ti.API()))

	err := sub.Start()
	if !assert.NoError(t, err) {
		return nil, err
	}

	t.Cleanup(func() { sub.Stop() })
	return sub, nil
}

func getEventHandles(t testing.TB, ti eventlog_test.APITester, sub *PullSubscription, numEvents uint) error {
	eventRecords, err := ReadNumEventsWithNotify(t, ti, sub, numEvents)
	if err != nil {
		return err
	}
	count := uint(len(eventRecords))
	if !assert.Equal(t, numEvents, count, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents)) {
		return fmt.Errorf("Missing events")
	}
	return nil
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
		return
	}

	channel := "testchannel"
	numEvents := []uint{10,100,1000,10000}

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
						sub, err := startSubscription(b, ti, channel)
						require.NoError(b, err)
						getEventHandles(b, ti, sub, v)
						err = assertNoMoreEvents(b, sub)
						assert.NoError(b, err)
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

	ti eventlog_test.APITester
}

func (s *GetEventsTestSuite) SetupSuite() {
	// Enable logger
	// pkglog.SetupLogger(seelog.Default, "debug")
	// fmt.Println("SetupSuite")

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

func (s *GetEventsTestSuite) TestReadOldEvents() {
	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// Get Events
	err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
	require.NoError(s.T(), err)
}

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
	err = getEventHandles(s.T(), s.ti, sub, s.numEvents)
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
		err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
		close(readyToStop)
		if !assert.NoError(s.T(), err) {
			return
		}
		// Purposefully don't call EvtNext the final time when it would normally return ERROR_NO_MORE_ITEMS.
		// This leaves the notify event set.
		// Wait for Stop() to finish
		<-stopped
		_, ok := <- sub.NotifyEventsAvailable
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
		err := getEventHandles(s.T(), s.ti, sub, s.numEvents)
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
		_, ok := <- sub.NotifyEventsAvailable
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

// Tests that NotifyEventsAvailable starts out set then becomes unset after calling GetEvents().
// This ensures the Windows Event Log API follows the behavior implied by the Microsoft example.
// https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events#pull-subscriptions
func (s *GetEventsTestSuite) TestChannelInitiallyNotified() {
	// Create sub
	sub, err := startSubscription(s.T(), s.ti, s.channelPath)
	require.NoError(s.T(), err)

	// TODO: How to remove this sleep?
	time.Sleep(100*time.Millisecond)

	select {
	case <- sub.NotifyEventsAvailable:
		break
	default:
		require.FailNow(s.T(), "NotifyEventsAvailable should not block the first time")
	}

	// should return empty
	err = assertNoMoreEvents(s.T(), sub)
	require.NoError(s.T(), err)

	// should block this time
	select {
	case <- sub.NotifyEventsAvailable:
		require.FailNow(s.T(), "NotifyEventsAvailable should block if no events available")
	default:
		break
	}
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
