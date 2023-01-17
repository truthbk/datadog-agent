// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build docker
// +build docker

package tailers

import (
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
)

// WrappedSource wraps a LogSource and adds/removes it to the logs-agent on
// start/stop.
type WrappedSource struct {
	// Source is the LogSource to add or remove
	Source *sources.LogSource

	// Sources is the container in which Source is added or removed.
	Sources *sources.LogSources

	onStopChan chan struct{}
}

// Start implements Tailer#Start.
func (t *WrappedSource) Start() error {

	// this method is typically called while the container launcher is handling
	// a channel message from `sources.AddSource`; if we send this
	// synchronously, it causes a deadlock because the added source is
	// delivered to the container launcher.  As a workaround, add the source
	// in a temporary goroutine.  The long-term fix is that launchers should
	// not be adding sources.
	go func() {
		t.onStopChan = make(chan struct{})
		t.Sources.AddSource(t.Source)
	}()

	return nil
}

// Stop implements Tailer#Stop.
func (t *WrappedSource) Stop() {
	// (see comment in Start())
	go func() {
		t.Sources.RemoveSource(t.Source)
		close(t.onStopChan)
	}()
}

// TODO
func (t *WrappedSource) OnStop() <-chan struct{} {
	return t.onStopChan
}
