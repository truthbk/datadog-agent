// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	"testing"

    evtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
)

func ReadNumEventsWithNotify(t testing.TB, ti eventlog_test.EventLogTestInterface, sub *PullSubscription, numEvents uint) []*EventRecord {
	eventRecords := make([]*EventRecord, 0)

	count := uint(0)
	eventLoop:
	for {
		select {
		case _, ok := <- sub.NotifyEventsAvailable:
			if !ok {
				break eventLoop
			}
			for {
				events, err := sub.GetEvents()
				require.NoError(t, err)
				if count == numEvents {
					require.Nil(t, events)
				} else {
					require.NotNil(t, events)
				}
				if events != nil {
					eventRecords = append(eventRecords, events...)
					count += uint(len(events))
				}
				if count >= numEvents {
					break eventLoop
				}
			}
		}
	}

	for _, eventRecord := range eventRecords {
		if eventRecord.EventRecordHandle == evtapi.EventRecordHandle(0) {
			require.FailNow(t, "EventRecordHandle must not be NULL")
		}
	}

	return eventRecords
}
