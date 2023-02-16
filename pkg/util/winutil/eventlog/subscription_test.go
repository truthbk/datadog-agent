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

func createEvents(t testing.TB, ti eventlog_test.EventLogTestInterface, channel string, numEvents uint) {
	// Report events
	err := ti.InstallSource(channel)
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
	eventRecords := ReadNumEvents(ti, sub, numEvents)
	count := uint(len(eventRecords))
	require.Equal(ti.T(), count, numEvents, fmt.Sprintf("Missing events, collected %d/%d events", count, numEvents))

	sub.Stop()
}

func TestGetEventHandles(t *testing.T) {
	testInterfaceNames := eventlog_test.GetEnabledTestInterfaces()

	channel := "testchannel"
	numEvents := uint(10)

	for _, tiName := range testInterfaceNames {
		t.Run(fmt.Sprintf("%sAPI", tiName), func(t *testing.T) {
			ti := eventlog_test.GetTestInterfaceByName(tiName, t)
			createEvents(t, ti, channel, numEvents)
			sub := startSubscription(t, ti, channel)
			getEventHandles(t, ti, sub, numEvents)
		})
	}
}

func TestBenchmarkTestGetEventHandles(t *testing.T) {
	if testing.Short() {
		return
	}

	channel := "testchannel"
	numEvents := []uint{10,100,1000,10000}

	for _, v := range numEvents {
		t.Run(fmt.Sprintf("%d", v), func(t *testing.T) {
			ti := eventlog_test.GetTestInterfaceByName("Mock", t)
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
