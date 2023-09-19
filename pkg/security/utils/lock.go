// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package utils

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.uber.org/atomic"
)

// Timeout the timeout
var Timeout = time.Second * 30

// RWMutex rwmutex version
type RWMutex struct {
	mutex  sync.RWMutex
	frames atomic.Value
	at     atomic.Value
}

func (i *RWMutex) rwlock(l func()) {
	buffer := make([]byte, 10000)
	n := runtime.Stack(buffer, false)

	got := make(chan bool)
	go func() {
		select {
		case <-got:
		case <-time.After(Timeout):
			err := "\n-- POTENTIAL DEADLOCK --\n\n"
			err += fmt.Sprintf("--  HOLDING THE LOCK SINCE %s  --\n", i.at.Load())
			err += fmt.Sprintf("%s\n", i.frames.Load())
			err += fmt.Sprintf("--  TRYING TO LOCK at %s  --\n", time.Now())
			err += fmt.Sprintf("%s\n", string(buffer[:n]))
			err += "\n-- POTENTIAL DEADLOCK --\n"
			panic(err)
		}
	}()

	l()
	i.at.Store(time.Now())

	// stop the timer
	got <- true

	// save the current stack
	i.frames.Store(string(buffer[:n]))
}

// Lock lock
func (i *RWMutex) Lock() {
	i.rwlock(i.mutex.Lock)
}

// Unlock unlock
func (i *RWMutex) Unlock() {
	i.frames.Store("")
	i.mutex.Unlock()
}

// RLock rlock
func (i *RWMutex) RLock() {
	i.rwlock(i.mutex.RLock)
}

// RUnlock runlock
func (i *RWMutex) RUnlock() {
	i.mutex.RUnlock()
}

// Mutex mutex version
type Mutex struct {
	mutex  sync.Mutex
	frames atomic.Value
	at     atomic.Value
}

func (i *Mutex) lock(l func()) {
	buffer := make([]byte, 10000)
	n := runtime.Stack(buffer, false)

	got := make(chan bool)
	go func() {
		select {
		case <-got:
		case <-time.After(Timeout):
			err := "\n-- POTENTIAL DEADLOCK --\n\n"
			err += fmt.Sprintf("--  HOLDING THE LOCK SINCE %s  --\n", i.at.Load())
			err += fmt.Sprintf("%s\n", i.frames.Load())
			err += fmt.Sprintf("--  TRYING TO LOCK at %s  --\n", time.Now())
			err += fmt.Sprintf("%s\n", string(buffer[:n]))
			err += "\n-- POTENTIAL DEADLOCK --\n"
			panic(err)
		}
	}()

	l()
	i.at.Store(time.Now())

	// stop the timer
	got <- true

	// save the current stack
	i.frames.Store(string(buffer[:n]))
}

// Lock lock
func (i *Mutex) Lock() {
	i.lock(i.mutex.Lock)
}

// Unlock unlock
func (i *Mutex) Unlock() {
	i.frames.Store("")
	i.mutex.Unlock()
}
