// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package model

import (
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/exp/slices"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

// Model describes the data model for the runtime security agent events
type Model struct {
	ExtraValidateFieldFnc func(field eval.Field, fieldValue eval.FieldValue) error
}

// ContainerContext holds the container context of an event
type ContainerContext struct {
	Releasable
	ID        string   `field:"id,handler:ResolveContainerID"`                              // SECLDoc[id] Definition:`ID of the container`
	CreatedAt uint64   `field:"created_at,handler:ResolveContainerCreatedAt"`               // SECLDoc[created_at] Definition:`Timestamp of the creation of the container``
	Tags      []string `field:"tags,handler:ResolveContainerTags,opts:skip_ad,weight:9999"` // SECLDoc[tags] Definition:`Tags of the container`
}

type Status uint32

const (
	// AnomalyDetection will trigger alerts each time an event is not part of the profile
	AnomalyDetection Status = 1 << iota
	// AutoSuppression will suppress any signal to events present on the profile
	AutoSuppression
	// WorkloadHardening will kill the process that triggered anomaly detection
	WorkloadHardening
)

func (s Status) IsEnabled(option Status) bool {
	return (s & option) != 0
}

func (s Status) String() string {
	var options []string
	if s.IsEnabled(AnomalyDetection) {
		options = append(options, "anomaly_detection")
	}
	if s.IsEnabled(AutoSuppression) {
		options = append(options, "auto_suppression")
	}
	if s.IsEnabled(WorkloadHardening) {
		options = append(options, "workload_hardening")
	}

	var res string
	for _, option := range options {
		if len(res) > 0 {
			res += ","
		}
		res += option
	}
	return res
}

// SecurityProfileContext holds the security context of the profile
type SecurityProfileContext struct {
	Name                       string      `field:"name"`                          // SECLDoc[name] Definition:`Name of the security profile`
	Status                     Status      `field:"status"`                        // SECLDoc[status] Definition:`Status of the security profile`
	Version                    string      `field:"version"`                       // SECLDoc[version] Definition:`Version of the security profile`
	Tags                       []string    `field:"tags"`                          // SECLDoc[tags] Definition:`Tags of the security profile`
	AnomalyDetectionEventTypes []EventType `field:"anomaly_detection_event_types"` // SECLDoc[anomaly_detection_event_types] Definition:`Event types enabled for anomaly detection`
}

// CanGenerateAnomaliesFor returns true if the current profile can generate anomalies for the provided event type
func (spc SecurityProfileContext) CanGenerateAnomaliesFor(evtType EventType) bool {
	return slices.Contains[EventType](spc.AnomalyDetectionEventTypes, evtType)
}

// CommonFields represents an event sent from the kernel
// genaccessors
type CommonFields struct {
	ID           string         `field:"-" json:"-"`
	Type         uint32         `field:"-"`
	Flags        uint32         `field:"-"`
	TimestampRaw uint64         `field:"event.timestamp,handler:ResolveEventTimestamp" json:"-"` // SECLDoc[event.timestamp] Definition:`Timestamp of the event`
	Timestamp    time.Time      `field:"-"`
	Rules        []*MatchedRule `field:"-"`

	// context shared with all events
	PIDContext             PIDContext             `field:"-" json:"-"`
	SpanContext            SpanContext            `field:"-" json:"-"`
	ProcessContext         *ProcessContext        `field:"process" event:"*"`
	ContainerContext       *ContainerContext      `field:"container"`
	NetworkContext         NetworkContext         `field:"network"`
	SecurityProfileContext SecurityProfileContext `field:"-"`

	// internal usage
	ProcessCacheEntry *ProcessCacheEntry `field:"-" json:"-"`

	// mark event with having error
	Error error `field:"-" json:"-"`

	// field resolution
	FieldHandlers FieldHandlers `field:"-" json:"-"`
}

func initMember(member reflect.Value, deja map[string]bool) {
	for i := 0; i < member.NumField(); i++ {
		field := member.Field(i)

		switch field.Kind() {
		case reflect.Ptr:
			if field.CanSet() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			if field.Elem().Kind() == reflect.Struct {
				name := field.Elem().Type().Name()
				if deja[name] {
					continue
				}
				deja[name] = true

				initMember(field.Elem(), deja)
			}
		case reflect.Struct:
			name := field.Type().Name()
			if deja[name] {
				continue
			}
			deja[name] = true

			initMember(field, deja)
		}
	}
}

// NewEvent returns a new event
func NewEvalEvent(handlers FieldHandlers) eval.Event {
	return &Event{
		CommonFields: CommonFields{
			ContainerContext: &ContainerContext{},
			FieldHandlers:    handlers,
		},
	}
}

// NewEvent returns a new event
func NewEvent(handlers FieldHandlers) *Event {
	return &Event{
		CommonFields: CommonFields{
			ContainerContext: &ContainerContext{},
			FieldHandlers:    handlers,
		},
	}
}

// NewEvent returns a new Event
func (m *Model) NewEvalEvent() eval.Event {
	return NewDefaultEvalEvent()
}

// NewEvent returns a new event
func MakeEvent() Event {
	return Event{
		CommonFields: CommonFields{
			ContainerContext: &ContainerContext{},
		},
	}
}

// NewDefaultEvent returns a new event using the default field handlers
func NewDefaultEvalEvent() eval.Event {
	return &Event{
		CommonFields: CommonFields{
			FieldHandlers:    &DefaultFieldHandlers{},
			ContainerContext: &ContainerContext{},
		},
	}
}

// NewDefaultEvent returns a new event using the default field handlers
func NewDefaultEvent() *Event {
	return NewDefaultEvalEvent().(*Event)
}

// NewDefaultEventWithType returns a new Event for the given type
func (m *Model) NewDefaultEventWithType(kind EventType) eval.Event {
	return &Event{
		CommonFields: CommonFields{
			Type:             uint32(kind),
			FieldHandlers:    &DefaultFieldHandlers{},
			ContainerContext: &ContainerContext{},
		},
	}
}

// Init initialize the event
func (e *Event) Init() {
	initMember(reflect.ValueOf(e).Elem(), map[string]bool{})
}

// IsSavedByActivityDumps return whether saved by AD
func (e *Event) IsSavedByActivityDumps() bool {
	return e.Flags&EventFlagsSavedByAD > 0
}

// IsSavedByActivityDumps return whether AD sample
func (e *Event) IsActivityDumpSample() bool {
	return e.Flags&EventFlagsActivityDumpSample > 0
}

// IsInProfile return true if the event was fount in the profile
func (e *Event) IsInProfile() bool {
	return e.Flags&EventFlagsSecurityProfileInProfile > 0
}

// AddToFlags adds a flag to the event
func (e *Event) AddToFlags(flag uint32) {
	e.Flags |= flag
}

// RemoveFromFlags remove a flag to the event
func (e *Event) RemoveFromFlags(flag uint32) {
	e.Flags ^= flag
}

// HasProfile returns true if we found a profile for that event
func (e *Event) HasProfile() bool {
	return e.SecurityProfileContext.Name != ""
}

// GetType returns the event type
func (e *Event) GetType() string {
	return EventType(e.Type).String()
}

// GetEventType returns the event type of the event
func (e *Event) GetEventType() EventType {
	return EventType(e.Type)
}

// GetTags returns the list of tags specific to this event
func (e *Event) GetTags() []string {
	tags := []string{"type:" + e.GetType()}

	// should already be resolved at this stage
	if len(e.ContainerContext.Tags) > 0 {
		tags = append(tags, e.ContainerContext.Tags...)
	}
	return tags
}

// ResolveProcessCacheEntry uses the field handler
func (ev *Event) ResolveProcessCacheEntry() (*ProcessCacheEntry, bool) {
	return ev.FieldHandlers.ResolveProcessCacheEntry(ev)
}

// ResolveEventTime uses the field handler
func (ev *Event) ResolveEventTime() time.Time {
	return ev.FieldHandlers.ResolveEventTime(ev)
}

// GetProcessService uses the field handler
func (ev *Event) GetProcessService() string {
	return ev.FieldHandlers.GetProcessService(ev)
}

// Releasable represents an object than can be released
type Releasable struct {
	onReleaseCallback func() `field:"-" json:"-"`
}

func (r *Releasable) CallReleaseCallback() {
	if r.onReleaseCallback != nil {
		r.onReleaseCallback()
	}
}

// SetReleaseCallback sets a callback to be called when the cache entry is released
func (r *Releasable) SetReleaseCallback(callback func()) {
	previousCallback := r.onReleaseCallback
	r.onReleaseCallback = func() {
		callback()
		if previousCallback != nil {
			previousCallback()
		}
	}
}

// Release triggers the callback
func (r *Releasable) OnRelease() {
	r.onReleaseCallback()
}

// MatchedRules contains the identification of one rule that has match
type MatchedRule struct {
	RuleID        string
	RuleVersion   string
	RuleTags      map[string]string
	PolicyName    string
	PolicyVersion string
}

// NewMatchedRule return a new MatchedRule instance
func NewMatchedRule(ruleID, ruleVersion string, ruleTags map[string]string, policyName, policyVersion string) *MatchedRule {
	return &MatchedRule{
		RuleID:        ruleID,
		RuleVersion:   ruleVersion,
		RuleTags:      ruleTags,
		PolicyName:    policyName,
		PolicyVersion: policyVersion,
	}
}

func (mr *MatchedRule) Match(mr2 *MatchedRule) bool {
	if mr2 == nil ||
		mr.RuleID != mr2.RuleID ||
		mr.RuleVersion != mr2.RuleVersion ||
		mr.PolicyName != mr2.PolicyName ||
		mr.PolicyVersion != mr2.PolicyVersion {
		return false
	}
	return true
}

// Append two lists, but avoiding duplicates
func AppendMatchedRule(list []*MatchedRule, toAdd []*MatchedRule) []*MatchedRule {
	for _, ta := range toAdd {
		found := false
		for _, l := range list {
			if l.Match(ta) { // rule already present
				found = true
				break
			}
		}
		if !found {
			list = append(list, ta)
		}
	}
	return list
}

// Retain the event
func (ev *Event) Retain() Event {
	if ev.ProcessCacheEntry != nil {
		ev.ProcessCacheEntry.Retain()
	}
	return *ev
}

// Release the event
func (ev *Event) Release() {
	if ev.ProcessCacheEntry != nil {
		ev.ProcessCacheEntry.Release()
	}
}

var zeroProcessContext ProcessContext

// ProcessCacheEntry this struct holds process context kept in the process tree
type ProcessCacheEntry struct {
	ProcessContext

	refCount  uint64                     `field:"-" json:"-"`
	onRelease func(_ *ProcessCacheEntry) `field:"-" json:"-"`
	releaseCb func()                     `field:"-" json:"-"`
}

// IsContainerRoot returns whether this is a top level process in the container ID
func (pc *ProcessCacheEntry) IsContainerRoot() bool {
	return pc.ContainerID != "" && pc.Ancestor != nil && pc.Ancestor.ContainerID == ""
}

// Reset the entry
func (pc *ProcessCacheEntry) Reset() {
	pc.ProcessContext = zeroProcessContext
	pc.refCount = 0
	pc.releaseCb = nil
}

// Retain increment ref counter
func (pc *ProcessCacheEntry) Retain() {
	pc.refCount++
}

// SetReleaseCallback set the callback called when the entry is released
func (pc *ProcessCacheEntry) SetReleaseCallback(callback func()) {
	previousCallback := pc.releaseCb
	pc.releaseCb = func() {
		callback()
		if previousCallback != nil {
			previousCallback()
		}
	}
}

// Release decrement and eventually release the entry
func (pc *ProcessCacheEntry) Release() {
	pc.refCount--
	if pc.refCount > 0 {
		return
	}

	if pc.onRelease != nil {
		pc.onRelease(pc)
	}

	if pc.releaseCb != nil {
		pc.releaseCb()
	}
}

// NewProcessCacheEntry returns a new process cache entry
func NewProcessCacheEntry(onRelease func(_ *ProcessCacheEntry)) *ProcessCacheEntry {
	return &ProcessCacheEntry{onRelease: onRelease}
}

// ProcessAncestorsIterator defines an iterator of ancestors
type ProcessAncestorsIterator struct {
	prev *ProcessCacheEntry
}

// Front returns the first element
func (it *ProcessAncestorsIterator) Front(ctx *eval.Context) unsafe.Pointer {
	if front := ctx.Event.(*Event).ProcessContext.Ancestor; front != nil {
		it.prev = front
		return unsafe.Pointer(front)
	}

	return nil
}

// Next returns the next element
func (it *ProcessAncestorsIterator) Next() unsafe.Pointer {
	if next := it.prev.Ancestor; next != nil {
		it.prev = next
		return unsafe.Pointer(next)
	}

	return nil
}

// HasParent returns whether the process has a parent
func (p *ProcessContext) HasParent() bool {
	return p.Parent != nil
}

// ProcessContext holds the process context of an event
type ProcessContext struct {
	Process

	Parent   *Process           `field:"parent,opts:exposed_at_event_root_only,check:HasParent"`
	Ancestor *ProcessCacheEntry `field:"ancestors,iterator:ProcessAncestorsIterator,check:IsNotKworker"`
}

// ExtraFieldHandlers handlers not hold by any field
type ExtraFieldHandlers interface {
	ResolveProcessCacheEntry(ev *Event) (*ProcessCacheEntry, bool)
	ResolveContainerContext(ev *Event) (*ContainerContext, bool)
	ResolveEventTime(ev *Event) time.Time
	GetProcessService(ev *Event) string
}

// ResolveProcessCacheEntry stub implementation
func (dfh *DefaultFieldHandlers) ResolveProcessCacheEntry(ev *Event) (*ProcessCacheEntry, bool) {
	return nil, false
}

// ResolveContainerContext stub implementation
func (dfh *DefaultFieldHandlers) ResolveContainerContext(ev *Event) (*ContainerContext, bool) {
	return nil, false
}

// ResolveEventTimestamp stub implementation
func (dfh *DefaultFieldHandlers) ResolveEventTime(ev *Event) time.Time {
	return ev.Timestamp
}

// GetProcessService stub implementation
func (dfh *DefaultFieldHandlers) GetProcessService(ev *Event) string {
	return ""
}

// NetworkContext represents the network context of the event
type NetworkContext struct {
	Device NetworkDeviceContext `field:"device"` // network device on which the network packet was captured

	L3Protocol  uint16        `field:"l3_protocol"` // SECLDoc[l3_protocol] Definition:`l3 protocol of the network packet` Constants:`L3 protocols`
	L4Protocol  uint16        `field:"l4_protocol"` // SECLDoc[l4_protocol] Definition:`l4 protocol of the network packet` Constants:`L4 protocols`
	Source      IPPortContext `field:"source"`      // source of the network packet
	Destination IPPortContext `field:"destination"` // destination of the network packet
	Size        uint32        `field:"size"`        // SECLDoc[size] Definition:`size in bytes of the network packet`
}

// DNSEvent represents a DNS event
type DNSEvent struct {
	ID    uint16 `field:"id" json:"-"`                                             // SECLDoc[id] Definition:`[Experimental] the DNS request ID`
	Name  string `field:"question.name,opts:length" op_override:"eval.DNSNameCmp"` // SECLDoc[question.name] Definition:`the queried domain name`
	Type  uint16 `field:"question.type"`                                           // SECLDoc[question.type] Definition:`a two octet code which specifies the DNS question type` Constants:`DNS qtypes`
	Class uint16 `field:"question.class"`                                          // SECLDoc[question.class] Definition:`the class looked up by the DNS question` Constants:`DNS qclasses`
	Size  uint16 `field:"question.length"`                                         // SECLDoc[question.length] Definition:`the total DNS request size in bytes`
	Count uint16 `field:"question.count"`                                          // SECLDoc[question.count] Definition:`the total count of questions in the DNS request`
}

// SpanContext describes a span context
type SpanContext struct {
	SpanID  uint64 `field:"_" json:"-"`
	TraceID uint64 `field:"_" json:"-"`
}
