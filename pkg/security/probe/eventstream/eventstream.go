// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package eventstream

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
	manager "github.com/DataDog/ebpf-manager"
)

const EventStreamMap = "events"

// EventStream describes the interface implemented by reordered perf maps or ring buffers
type EventStream interface {
	Init(*manager.Manager, *config.Config) error
	SetMonitor(LostEventCounter)
	Start(*sync.WaitGroup) error
	Pause() error
	Resume() error
}
