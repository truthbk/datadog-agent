// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package windowsevent

import (
	"testing"
	"time"

	"github.com/cihub/seelog"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	auditor "github.com/DataDog/datadog-agent/pkg/logs/auditor/mock"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/launchers"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline/mock"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/status"
	pkglog "github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"
)

type LauncherTestSuite struct {
	suite.Suite
	configID string

	channelPath string
	eventSource string
	query       string
	tailerType  string
	testAPI     string
	numEvents   uint

	ti eventlog_test.APITester

	outputChan       chan *message.Message
	pipelineProvider pipeline.Provider
	source           *sources.LogSource
	s                *Launcher
}

func (s *LauncherTestSuite) SetupSuite() {
	var err error
	// Enable logger
	if s.numEvents == 0 {
		pkglog.SetupLogger(seelog.Default, "debug")
	}

	s.ti = eventlog_test.GetAPITesterByName(s.testAPI, s.T())
	err = s.ti.InstallChannel(s.channelPath)
	require.NoError(s.T(), err)
	err = s.ti.InstallSource(s.channelPath, s.eventSource)
	require.NoError(s.T(), err)
	err = s.ti.API().EvtClearLog(s.channelPath)
	require.NoError(s.T(), err)
}

func (s *LauncherTestSuite) TearDownSuite() {
	s.ti.RemoveSource(s.channelPath, s.eventSource)
	s.ti.RemoveChannel(s.channelPath)
}

func (s *LauncherTestSuite) SetupTest() {
	s.pipelineProvider = mock.NewMockProvider()
	s.outputChan = s.pipelineProvider.NextPipelineChan()
	s.source = sources.NewLogSource("",
		&config.LogsConfig{
			Type:        s.tailerType,
			Identifier:  s.configID,
			ChannelPath: s.channelPath,
			Query:       s.query})
	s.s = NewLauncher()
	s.s.evtapi = s.ti.API()
	status.InitStatus(util.CreateSources([]*sources.LogSource{s.source}))
	s.s.Start(launchers.NewMockSourceProvider(), s.pipelineProvider, auditor.NewRegistry())
	s.s.sources <- s.source
	if len(s.s.tailers) != 1 {
		time.Sleep(500 * time.Millisecond)
	}
	if !s.source.Status.IsSuccess() {
		s.FailNow("failed to create tailer")
	}
}

func (s *LauncherTestSuite) TearDownTest() {
	status.Clear()
	s.s.Stop()
}

func TestLauncherTestSuite(t *testing.T) {
	var s LauncherTestSuite
	s.channelPath = "dd-test-channel-loglauncher"
	s.eventSource = "dd-test-source-loglauncher"
	s.query = "*"
	s.tailerType = "windows_event"
	s.testAPI = "Windows"
	s.numEvents = 1000
	suite.Run(t, &s)
}

func (s *LauncherTestSuite) TestReadEvents() {
	err := s.ti.GenerateEvents(s.eventSource, s.numEvents)
	require.NoError(s.T(), err)

	totalEvents := uint(0)
	for i := uint(0); i < s.numEvents; i++ {
		msg := <- s.outputChan
		require.NotEmpty(s.T(), msg.Content, "Message must not be empty")
		totalEvents += 1
	}
	require.Equal(s.T(), s.numEvents, totalEvents, "Received %d/%d events", totalEvents, s.numEvents)
}

func TestShouldSanitizeConfig(t *testing.T) {
	launcher := NewLauncher()
	require.Equal(t, "*", launcher.sanitizedConfig(&config.LogsConfig{ChannelPath: "System", Query: ""}).Query)
}
