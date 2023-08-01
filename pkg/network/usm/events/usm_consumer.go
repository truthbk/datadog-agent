// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package events

import (
	"github.com/DataDog/datadog-agent/pkg/eventmonitor"
	"github.com/DataDog/datadog-agent/pkg/runtime"
	smodel "github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

type USMConsumer struct{}

func (n *USMConsumer) Start() error {
	cpuNum := runtime.NumVCPU()
	callbackRunner := make(chan func(), pendingCallbacksQueueSize)
	pm.callbackRunnersWG.Add(cpm)
	for i := 0; i < cpuNum; i++ {
		go func() {
			defer pm.callbackRunnersWG.Done()
			for call := range pm.callbackRunner {
				if call != nil {
					call()
				}
			}
		}()
	}
}

func (n *USMConsumer) Stop() {
	// TODO:  Wait for all callback runners to stop. We need to be careful here not create a deadlock as this function
	// is called in the context of the event monitor module, so the callbackRunner channel is closed before waiting on anything
}

// ID returns id for process monitor
func (n *USMConsumer) ID() string {
	return "USM"
}

// NewUSMConsumer returns a new USMConsumer instance
func NewUSMConsumer(evm *eventmonitor.EventMonitor) (*USMConsumer, error) {
	eventHandler := newEventHandler()
	if err := evm.AddEventTypeHandler(smodel.ExecEventType, eventHandler); err != nil {
		return nil, err
	}
	if err := evm.AddEventTypeHandler(smodel.ExitEventType, eventHandler); err != nil {
		return nil, err
	}

	return &USMConsumer{}, nil
}
