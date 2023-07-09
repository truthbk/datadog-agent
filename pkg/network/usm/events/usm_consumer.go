// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package events

import (
	"github.com/DataDog/datadog-agent/pkg/eventmonitor"
	smodel "github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

type USMConsumer struct{}

func (n *USMConsumer) Start() error {
	return nil
}

func (n *USMConsumer) Stop() {
}

// ID returns id for process monitor
func (n *USMConsumer) ID() string {
	return "USM"
}

// NewUSMConsumer returns a new USMConsumer instance
func NewUSMConsumer(evm *eventmonitor.EventMonitor) (*USMConsumer, error) {
	h := Handler()
	if err := evm.AddEventTypeHandler(smodel.ExecEventType, h); err != nil {
		return nil, err
	}
	if err := evm.AddEventTypeHandler(smodel.ExitEventType, h); err != nil {
		return nil, err
	}

	return &USMConsumer{}, nil
}
