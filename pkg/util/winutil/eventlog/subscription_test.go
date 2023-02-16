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

    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
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

func TestGetEventHandles(t *testing.T) {
	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	var err error
	channel := "testchannel"
	numEvents := uint(10)

	for _, tiName := range testInterfaceNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			ti := eventlog_test.GetTestInterfaceByName(tiName, t)

			// Report events
			err = ti.InstallSource(channel)
			require.NoError(t, err)
			err = ti.GenerateEvents(channel, numEvents)
			require.NoError(t, err)

			// Create sub
			sub := NewPullSubscription(
				channel,
				"*",
				WithEventLoopWaitMs(50),
				WithWindowsEventLogAPI(ti.EventLogAPI()))

			err = sub.Start()
			require.NoError(t, err)

			eventRecords := ReadNumEvents(ti, sub, numEvents)
			count := uint(len(eventRecords))
			require.Equal(ti.T(), count, numEvents, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents))

			sub.Stop()
		})
	}
}
