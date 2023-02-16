// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog

import (
	// "fmt"

    evtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/test"

	"github.com/stretchr/testify/require"
)

func ReadNumEvents(ti eventlog_test.EventLogTestInterface, sub *PullSubscription, numEvents uint) []*EventRecord {
	eventRecords := make([]*EventRecord, numEvents)

	count := uint(0)
	eventLoop:
	for {
		select {
		case eventRecord := <- sub.EventRecords:
			require.NotNil(ti.T(), eventRecord)
			if eventRecord.EventRecordHandle == evtapi.EventRecordHandle(0) {
				require.FailNow(ti.T(), "EventRecordHandle should not be NULL")
			}
			// fmt.Printf("handle: %#x\n", eventRecord.EventRecordHandle)
			eventRecords[count] = eventRecord
			count += 1
			if count >= numEvents {
				break eventLoop
			}
		}
	}

	return eventRecords
}
