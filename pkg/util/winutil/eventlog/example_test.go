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

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
)

// Example usage of the eventlog utility library to get event records from the Windows Event Log
// while using a channel to be notified when new events are available.
func testExampleNotifyChannel(t testing.TB, ti eventlog_test.EventLogTestInterface, stop chan struct{}, done chan struct{}, channelPath string, numEvents uint) {
	defer close(done)

	// Choose the Windows Event Log API implementation
	// Windows API
	//   winevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
	//   api = winevtapi.NewWindowsEventAPI()
	// Mock API
	//   mockevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/mock"
	//   api = mockevtapi.NewMockWindowsEventAPI()
	// For this test the API implementation is selected by the test runner
	evtapi := ti.EventLogAPI()

	// Create the subscription
	sub := NewPullSubscription(
		channelPath,
		"*",
		WithWindowsEventLogAPI(evtapi))

	// Start the subscription
	err := sub.Start()
	require.NoError(t, err)

	// Get events until stop is set
	outerLoop:
	for {
		select {
		case <- stop:
			break outerLoop
		case _, ok := <- sub.NotifyEventsAvailable:
			if !ok {
				// The channel is closed, this indicates an error or that sub.Stop() was called
				break outerLoop
			}
			// Get the events
			events, err := sub.GetEvents()
			if err != nil {
				// error
				break outerLoop
			}
			if events == nil {
				// no more events, go back to waiting on NotifyEventsAvailable
				continue outerLoop
			}

			// handle the event
			for _, eventRecord := range events {
				// do something with the event
				// ...
				// close the event when done
				evtapidef.EvtCloseRecord(evtapi, eventRecord.EventRecordHandle)
			}
			break outerLoop
		}
	}

	// Cleanup the subscription
	sub.Stop()
}

func TestExampleNotifyChannel(t *testing.T) {
	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	channelPath := "testchannel"
	numEvents := uint(10)
	for _, tiName := range testInterfaceNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			ti := eventlog_test.GetTestInterfaceByName(tiName, t)
			// Create some test events
			createLog(t, ti, channelPath)
			err := ti.GenerateEvents(channelPath, numEvents)
			require.NoError(t, err)
			// Create stop channel to use as example of an external signal to shutdown
			stop := make(chan struct{})
			done := make(chan struct{})

			// Start our example implementation
			go testExampleNotifyChannel(t, ti, stop, done, channelPath, numEvents)

			// Create some test events while that's running
			for i := 0; i < 3; i++ {
				err := ti.GenerateEvents(channelPath, numEvents)
				require.NoError(t, err)
				// simulate some delay in event generation
				time.Sleep(100*time.Millisecond)
			}
			// Stop the event collector
			close(stop)
			<-done
		})
	}
}

