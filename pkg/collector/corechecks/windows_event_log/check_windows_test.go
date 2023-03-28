// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package evtlog

import (
	"fmt"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/stretchr/testify/mock"
)

type GetEventsTestSuite struct {
	suite.Suite

	channelPath string
	testAPI     string
	numEvents   uint

	sender *mocksender.MockSender
	ti eventlog_test.APITester
}

func (s *GetEventsTestSuite) SetupSuite() {
	s.ti = eventlog_test.GetAPITesterByName(s.testAPI, s.T())
	err := s.ti.InstallChannel(s.channelPath)
	require.NoError(s.T(), err)
	err = s.ti.InstallSource(s.channelPath, "testsource")
	require.NoError(s.T(), err)
	s.sender = mocksender.NewMockSender("")
}

func (s *GetEventsTestSuite) TearDownSuite() {
	s.ti.RemoveSource(s.channelPath, "testsource")
	s.ti.RemoveChannel(s.channelPath)
}

func (s *GetEventsTestSuite) SetupTest() {
	// Ensure the log is empty
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
	s.sender.ResetCalls()
}

func (s *GetEventsTestSuite) TearDownTest() {
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
	s.sender.ResetCalls()
}

func TestLaunchGetEventsTestSuite(t *testing.T) {
	testerNames := eventlog_test.GetEnabledAPITesters()

	for _, tiName := range testerNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			var s GetEventsTestSuite
			s.channelPath = "testchannel"
			s.testAPI = tiName
			s.numEvents = 1000
			suite.Run(t, &s)
		})
	}
}

func readEvents(check *Check, senderEventCall *mock.Call, numEvents uint) uint {
	eventsCollected := uint(0)
	prevEventsCollected := uint(0)
	senderEventCall.Run(func (args mock.Arguments) {
		eventsCollected += 1
	})
	for {
		check.Run()
		if eventsCollected == numEvents || prevEventsCollected == eventsCollected{
			break
		}
		prevEventsCollected = eventsCollected
	}
	return eventsCollected
}

func (s *GetEventsTestSuite) TestGetEvents() {
	// Put events in the log
	err := s.ti.GenerateEvents(s.channelPath, s.numEvents)
	require.NoError(s.T(), err)

	instanceConfig := []byte(fmt.Sprintf(`
path: %s
start: old
`,
	s.channelPath))

	check := new(Check)
	check.evtapi = s.ti.API()
	err = check.Configure(integration.FakeConfigHash, instanceConfig, nil, "test")
	require.NoError(s.T(), err)
	defer check.Cancel()

	mocksender.SetSender(s.sender, check.ID())
	s.sender.On("Commit").Return()
	senderEventCall := s.sender.On("Event", mock.Anything)

	eventsCollected := readEvents(check, senderEventCall, s.numEvents)

	require.Equal(s.T(), s.numEvents, eventsCollected)
	s.sender.AssertExpectations(s.T())
}

func BenchmarkGetEvents(b *testing.B) {
	channelPath := "testchannel"
	numEvents := []uint{10, 100, 1000}
	batchCounts := []uint{1, 10, 100, 1000}

	testerNames := eventlog_test.GetEnabledAPITesters()

	sender := mocksender.NewMockSender("")
	sender.On("Commit").Return()
	senderEventCall := sender.On("Event", mock.Anything)

	bench_startTime := time.Now()
	bench_total_events := uint(0)
	for _, tiName := range testerNames {
		for _, v := range numEvents {
			// setup log
			ti := eventlog_test.GetAPITesterByName(tiName, b)
			err := ti.InstallChannel(channelPath)
			require.NoError(b, err)
			err = ti.InstallSource(channelPath, "testsource")
			require.NoError(b, err)
			err = ti.API().EvtClearLog(channelPath)
			require.NoError(b, err)
			err = ti.GenerateEvents(channelPath, v)
			require.NoError(b, err)

			for _, batchCount := range batchCounts {
				if batchCount > v {
					continue
				}
				b.Run(fmt.Sprintf("%vAPI/%dEvents/%dBatch", tiName, v, batchCount), func(b *testing.B) {
					// setup check
					instanceConfig := []byte(fmt.Sprintf(`
path: %s
start: old
payload_size: %d
`,
					channelPath, batchCount))

					// read the log b.N times
					b.ResetTimer()
					startTime := time.Now()
					total_events := uint(0)
					for i:= 0; i < b.N; i++ {
						check := new(Check)
						check.evtapi = ti.API()
						err = check.Configure(integration.FakeConfigHash, instanceConfig, nil, "test")
						require.NoError(b, err)
						mocksender.SetSender(sender, check.ID())

						total_events += readEvents(check, senderEventCall, v)

						check.Cancel()
						sender.ResetCalls()
					}

					// TODO: Use b.Elapsed in go1.20
					elapsed := time.Since(startTime)
					b.Logf("%.2f events/s (%.3fs) N=%d", float64(total_events)/elapsed.Seconds(), elapsed.Seconds(), b.N)
					bench_total_events += total_events
				})
			}
		}
	}

	elapsed := time.Since(bench_startTime)
	b.Logf("Benchmark total: %d events %.2f events/s (%.3fs)", bench_total_events, float64(bench_total_events)/elapsed.Seconds(), elapsed.Seconds())
}
