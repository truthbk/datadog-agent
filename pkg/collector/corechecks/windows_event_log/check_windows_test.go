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

	ti eventlog_test.APITester
}

func (s *GetEventsTestSuite) SetupSuite() {
	s.ti = eventlog_test.GetAPITesterByName(s.testAPI, s.T())
	err := s.ti.InstallChannel(s.channelPath)
	require.NoError(s.T(), err)
	err = s.ti.InstallSource(s.channelPath, "testsource")
	require.NoError(s.T(), err)
}

func (s *GetEventsTestSuite) TearDownSuite() {
	s.ti.RemoveSource(s.channelPath, "testsource")
	s.ti.RemoveChannel(s.channelPath)
}

func (s *GetEventsTestSuite) SetupTest() {
	// Ensure the log is empty
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)

}

func (s *GetEventsTestSuite) TearDownTest() {
	err := s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
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

	sender := mocksender.NewMockSender(check.ID())

	sender.On("Commit").Return().Times(1)
	sender.On("Event", mock.Anything).Return().Times(int(s.numEvents))
	check.Run()

	sender.AssertExpectations(s.T())
	sender.AssertNumberOfCalls(s.T(), "Commit", 1)
}
