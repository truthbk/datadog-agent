// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package windowsevent

import (
	"fmt"
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

func (suite *LauncherTestSuite) SetupSuite() {
	var err error
	// fmt.Println("SetupSuite")
	// Enable logger
	pkglog.SetupLogger(seelog.Default, "debug")

	suite.ti = eventlog_test.GetAPITesterByName(suite.testAPI, suite.T())
	err = suite.ti.InstallChannel(suite.channelPath)
	require.NoError(suite.T(), err)
	err = suite.ti.InstallSource(suite.channelPath, suite.eventSource)
	require.NoError(suite.T(), err)
	err = suite.ti.API().EvtClearLog(suite.channelPath)
	require.NoError(suite.T(), err)
}

func (suite *LauncherTestSuite) TearDownSuite() {
	// fmt.Println("TearDownSuite")
	suite.ti.RemoveSource(suite.channelPath, suite.eventSource)
	suite.ti.RemoveChannel(suite.channelPath)
}

func (suite *LauncherTestSuite) SetupTest() {
	suite.pipelineProvider = mock.NewMockProvider()
	suite.outputChan = suite.pipelineProvider.NextPipelineChan()
	suite.source = sources.NewLogSource("",
		&config.LogsConfig{
			Type:        suite.tailerType,
			Identifier:  suite.configID,
			ChannelPath: suite.channelPath,
			Query:       suite.query})
	suite.s = NewLauncher()
	suite.s.evtapi = suite.ti.API()
	status.InitStatus(util.CreateSources([]*sources.LogSource{suite.source}))
	suite.s.Start(launchers.NewMockSourceProvider(), suite.pipelineProvider, auditor.NewRegistry())
	// fmt.Println("sending source")
	suite.s.sources <- suite.source
	// fmt.Println("sent source")
	if len(suite.s.tailers) != 1 {
		time.Sleep(500 * time.Millisecond)
	}
	if suite.source.Status.IsSuccess() {
		// fmt.Println("success")
	} else {
		// fmt.Println("failure")
		suite.FailNow("failed to create tailer")
	}
}

func (suite *LauncherTestSuite) TearDownTest() {
	// fmt.Println("TearDownTest")
	status.Clear()
	suite.s.Stop()
}

func TestLauncherTestSuite(t *testing.T) {
	var s LauncherTestSuite
	s.channelPath = "dd-test-channel-loglauncher"
	s.eventSource = "dd-test-source-loglauncher"
	s.query = "*"
	s.tailerType = "windows_event"
	s.testAPI = "Windows"
	s.numEvents = 1
	suite.Run(t, &s)
}

func (suite *LauncherTestSuite) TestReadEvents() {
	err := suite.ti.GenerateEvents(suite.eventSource, suite.numEvents)
	require.NoError(suite.T(), err)
	// fmt.Println("TestReadEvents")
	msg := <-suite.outputChan
	fmt.Println(msg)
	suite.Equal("hello world", string(msg.Content))
}

func TestShouldSanitizeConfig(t *testing.T) {
	launcher := NewLauncher()
	require.Equal(t, "*", launcher.sanitizedConfig(&config.LogsConfig{ChannelPath: "System", Query: ""}).Query)
}
