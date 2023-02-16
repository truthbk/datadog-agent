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

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    winevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
    mockevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/mock"

	"github.com/stretchr/testify/assert"
)

func get_test_apis() []evtapidef.IWindowsEventLogAPI {

	var apis []evtapidef.IWindowsEventLogAPI

	apis = append(apis, mockevtapi.NewMockWindowsEventLogAPI())

	if testing.Short() == false {
		apis = append(apis, winevtapi.NewWindowsEventLogAPI())
	}

	return apis
}

func TestInvalidChannel(t *testing.T) {
	apis := get_test_apis()

	for _, api := range apis {
		t.Run(fmt.Sprintf("%s API", api.API_Name()), func(t *testing.T) {
			sub := NewPullSubscription(
				"nonexistentchannel",
				"*",
				WithEventLoopWaitMs(50),
				WithWindowsEventLogAPI(api))

			err := sub.Start()
			assert.Error(t, err)
		})
	}
}
