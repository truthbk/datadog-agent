// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package probe

import (
	"context"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/eventmonitor/config"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-go/v5/statsd"
	"golang.org/x/time/rate"
)

// EventHandler represents an handler for the events sent by the probe
type EventHandler interface {
	HandleEvent(event *model.Event)
}

// CustomEventHandler represents an handler for the custom events sent by the probe
type CustomEventHandler interface {
	HandleCustomEvent(rule *rules.Rule, event *events.CustomEvent)
}

// NotifyDiscarderPushedCallback describe the callback used to retrieve pushed discarders information
type NotifyDiscarderPushedCallback func(eventType string, event *model.Event, field string)

var (
	// defaultEventTypes event types used whatever the event handlers or the rules
	defaultEventTypes = []eval.EventType{
		model.ForkEventType.String(),
		model.ExecEventType.String(),
		model.ExecEventType.String(),
	}
)

// Probe represents the runtime security eBPF probe in charge of
// setting up the required kProbes and decoding events sent from the kernel
type Probe struct {
	PlatformProbe

	// Constants and configuration
	Opts         Opts
	Config       *config.Config
	StatsdClient statsd.ClientInterface
	startTime    time.Time
	ctx          context.Context
	cancelFnc    context.CancelFunc
	wg           sync.WaitGroup

	// Events section
	eventHandlers       [model.MaxAllEventType][]EventHandler
	customEventHandlers [model.MaxAllEventType][]CustomEventHandler

	// internals
	resolvers *resolvers.Resolvers
	event     *model.Event
	scrubber  *procutil.DataScrubber

	// Approvers / discarders section
	discarderRateLimiter               *rate.Limiter
	notifyDiscarderPushedCallbacks     []NotifyDiscarderPushedCallback
	notifyDiscarderPushedCallbacksLock sync.Mutex

	constantOffsets map[string]uint64
	runtimeCompiled bool

	isRuntimeDiscarded bool
}

// GetResolvers returns the resolvers of Probe
func (p *Probe) GetResolvers() *resolvers.Resolvers {
	return p.resolvers
}
