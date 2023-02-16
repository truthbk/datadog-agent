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

    mockevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/mock"

	"github.com/stretchr/testify/assert"
)

func fetchAllEvents(sub *PullSubscription) {


}

func TestBenchmarkReadMock(t *testing.T) {

	channel := "testchannel"
	mockapi := mockevtapi.NewMockWindowsEventLogAPI()

	numEvents := uint(100)

	err := mockapi.AddEventLog(channel)
	assert.NoError(t, err)
	err = mockapi.GenerateEvents(channel, numEvents)
	assert.NoError(t, err)

	sub := NewPullSubscription(
		channel,
		"*",
		WithEventLoopWaitMs(50),
		WithWindowsEventLogAPI(mockapi))

	err = sub.Start()
	assert.NoError(t, err)


	count := uint(0)
	eventLoop:
	for {
		select {
		case eventRecord := <- sub.EventRecords:
			count += 1
			if count >= numEvents {
				break eventLoop
			}
			if eventRecord == nil {
				break eventLoop
			}
			fmt.Println(eventRecord.EventRecordHandle)
		}
	}

	sub.Stop()

	fmt.Println("done")
}
