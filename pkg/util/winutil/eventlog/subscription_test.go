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
				WithEventLoopWaitMs(50),
				WithWindowsEventLogAPI(ti.EventLogAPI()))

			err := sub.Start()
			require.Error(t, err)
		})
	}
}

func createEvents(t testing.TB, ti eventlog_test.EventLogTestInterface, channel string, numEvents uint) {
	// Report events
	err := ti.InstallChannel(channel)
	require.NoError(t, err)
	err = ti.EventLogAPI().EvtClearLog(channel)
	require.NoError(t, err)
	err = ti.InstallSource(channel, "testsource")
	require.NoError(t, err)
	err = ti.GenerateEvents(channel, numEvents)
	require.NoError(t, err)
}

func startSubscription(t testing.TB, ti eventlog_test.EventLogTestInterface, channel string) *PullSubscription {
	// Create sub
	sub := NewPullSubscription(
		channel,
		"*",
		WithEventLoopWaitMs(50),
		WithWindowsEventLogAPI(ti.EventLogAPI()))

	err := sub.Start()
	require.NoError(t, err)
	return sub
}

func getEventHandles(t testing.TB, ti eventlog_test.EventLogTestInterface, sub *PullSubscription, numEvents uint) {
	eventRecords := ReadNumEventsWithNotify(t, ti, sub, numEvents)
	count := uint(len(eventRecords))
	require.Equal(t, count, numEvents, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents))

	sub.Stop()
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
				createEvents(t, ti, channel, v)
				result := testing.Benchmark(func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						sub := startSubscription(b, ti, channel)
						getEventHandles(b, ti, sub, v)
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

func (s *GetEventsTestSuite) TestStopWhileWaiting() {
	// Create subscription
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	readyToStop := make(chan struct{})
	go func() {
		// Read all events
		getEventHandles(s.T(), s.ti, sub, s.numEvents)
		close(readyToStop)
		// block on events available notification
		select {
		case _, ok := <- sub.NotifyEventsAvailable:
			require.False(s.T(), ok, "Notify channel should be closed after Stop()")
		}
	}()

	<-readyToStop
	sub.Stop()
}

func (s *GetEventsTestSuite) TestUnusedNotifyChannel() {
	// Create sub
	sub := startSubscription(s.T(), s.ti, s.channelPath)

	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	// Don't wait on the channel, just get events
	getEventHandles(s.T(), s.ti, sub, s.numEvents)

	sub.Stop()
}


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
	events, err := sub.GetEvents()
	require.NoError(s.T(), err)
	require.Nil(s.T(), events)

	// should block this time
	select {
	case <- sub.NotifyEventsAvailable:
		require.FailNow(s.T(), "NotifyEventsAvailable should block if no events available")
	default:
		break
	}

	sub.Stop()
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
