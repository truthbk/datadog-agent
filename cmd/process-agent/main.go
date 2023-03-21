// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows
// +build !windows

package main

/*
// This cgo directive is what actually causes jemalloc to be linked in to the
// final Go executable
#cgo CFLAGS: -I. -I/usr/include/jemalloc/
#cgo LDFLAGS: -Wl,-Bstatic -ljemalloc -Wl,-Bdynamic -lm
#include <jemalloc/jemalloc.h>
void _refresh_jemalloc_stats() {
	// You just need to pass something not-null into the "epoch" mallctl.
	size_t random_something = 1;
	mallctl("epoch", NULL, NULL, &random_something, sizeof(random_something));
}
int _get_jemalloc_active() {
	size_t stat, stat_size;
	stat = 0;
	stat_size = sizeof(stat);
	mallctl("stats.active", &stat, &stat_size, NULL, 0);
	return (int)stat;
}
*/
import "C"

import (
	"expvar"
	"sync"

	"github.com/DataDog/datadog-agent/cmd/process-agent/command"
)

const useWinParams = false

func rootCmdRun(globalParams *command.GlobalParams) {
	exit := make(chan struct{})

	// Invoke the Agent
	runAgent(globalParams, exit)
}

func init() {
	var refreshLock sync.Mutex
	expvar.Publish("jemalloc_allocated", expvar.Func(func() interface{} {
		refreshLock.Lock()
		defer refreshLock.Unlock()
		C._refresh_jemalloc_stats()
		return C._get_jemalloc_active()
	}))
}
