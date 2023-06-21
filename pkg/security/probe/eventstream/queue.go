// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package eventstream

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
	manager "github.com/DataDog/ebpf-manager"
)

const EventQueueName = "event-queue"

type KernelEvent struct {
	CPU  int
	Data []byte
}

type eventQueueState int

const (
	paused eventQueueState = iota
	running
)

type EventQueue struct {
	state            eventQueueState
	stateChan        chan eventQueueState
	sources          []EventStream
	eventChan        chan *KernelEvent
	handler          func(*KernelEvent)
	lostEventCounter LostEventCounter
}

func (eq *EventQueue) Init(m *manager.Manager, cfg *config.Config) error {
	for _, sources := range eq.sources {
		if err := sources.Init(m, cfg); err != nil {
			return err
		}
	}
	return nil
}

func (eq *EventQueue) SetMonitor(lostEventCounter LostEventCounter) {
	eq.lostEventCounter = lostEventCounter
	for _, source := range eq.sources {
		source.SetMonitor(lostEventCounter)
	}
}

// Start the event stream.
func (eq *EventQueue) Start(wg *sync.WaitGroup) error {
	wg.Add(1)

	var err error
	go func() {
		defer wg.Done()

		eq.state = running
		var ok bool

		for {
			switch eq.state {
			case paused:
				eq.state, ok = <-eq.stateChan
				if !ok {
					return
				}
				break
			case running:
				select {
				case eq.state, ok = <-eq.stateChan:
					if !ok {
						return
					}
					break
				default:
					kevent, ok := <-eq.eventChan
					if !ok {
						return
					}
					eq.handler(kevent)
					break
				}
				break
			default:
				err = fmt.Errorf("invalid EventQueue state (%d)", eq.state)
			}
		}
	}()

	for _, source := range eq.sources {
		if err := source.Start(wg); err != nil {
			return err
		}
	}

	return err
}

// Pause the event stream.
func (eq *EventQueue) Pause() error {
	eq.stateChan <- paused
	return nil
}

// Resume the event stream.
func (eq *EventQueue) Resume() error {
	eq.stateChan <- running
	return nil
}

func (eq *EventQueue) handleLostEvent(kevent *KernelEvent) {
	// if eq.lostEventCounter != nil {
	// 	eq.lostEventCounter.CountLostEvent(1, EventQueueName, kevent.CPU)
	// }
}

func (eq *EventQueue) Queue(kevent *KernelEvent) {
	select {
	case eq.eventChan <- kevent:
		break
	default:
		oldEvent := <-eq.eventChan
		select {
		case eq.eventChan <- kevent:
			break
		default:
			eq.handleLostEvent(kevent)
			break
		}
		eq.handleLostEvent(oldEvent)
		break
	}
}

func (eq *EventQueue) AddEventSource(source EventStream) {
	eq.sources = append(eq.sources, source)
}

func NewEventQueue(capacity int, handler func(kevent *KernelEvent)) *EventQueue {
	return &EventQueue{
		state:     paused,
		stateChan: make(chan eventQueueState),
		eventChan: make(chan *KernelEvent, capacity),
		handler:   handler,
	}
}
