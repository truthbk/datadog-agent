// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package serializers

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	jwriter "github.com/mailru/easyjson/jwriter"
)

func MarshalEvent(event *model.Event, probe *resolvers.Resolvers) ([]byte, error) {
	s := NewEventSerializer(event, probe)
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	s.MarshalEasyJSON(w)
	return w.BuildBytes()
}

func MarshalCustomEvent(event *events.CustomEvent) ([]byte, error) {
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	event.MarshalEasyJSON(w)
	return w.BuildBytes()
}

// ContainerContextSerializer serializes a container context to JSON
// easyjson:json
type ContainerContextSerializer struct {
	// Container ID
	ID string `json:"id,omitempty"`
	// Creation time of the container
	CreatedAt *utils.EasyjsonTime `json:"created_at,omitempty"`
}

// EventContextSerializer serializes an event context to JSON
// easyjson:json
type EventContextSerializer struct {
	// Event name
	Name string `json:"name,omitempty"`
	// Event category
	Category string `json:"category,omitempty"`
	// Event outcome
	Outcome string `json:"outcome,omitempty"`
}

// SecurityProfileContextSerializer serializes the security profile context in an event
type SecurityProfileContextSerializer struct {
	// Name of the security profile
	Name string `json:"name"`
	// Status defines in which state the security profile was when the event was triggered
	Status string `json:"status"`
	// Version of the profile in use
	Version string `json:"version"`
	// List of tags associated to this profile
	Tags []string `json:"tags"`
}

func getUint64Pointer(i *uint64) *uint64 {
	if *i == 0 {
		return nil
	}
	return i
}

func getUint32Pointer(i *uint32) *uint32 {
	if *i == 0 {
		return nil
	}
	return i
}

func getTimeIfNotZero(t time.Time) *utils.EasyjsonTime {
	if t.IsZero() {
		return nil
	}
	tt := utils.NewEasyjsonTime(t)
	return &tt
}

func newDNSEventSerializer(d *model.DNSEvent) *DNSEventSerializer {
	return &DNSEventSerializer{
		ID: d.ID,
		Question: DNSQuestionSerializer{
			Class: model.QClass(d.Class).String(),
			Type:  model.QType(d.Type).String(),
			Name:  d.Name,
			Size:  d.Size,
			Count: d.Count,
		},
	}
}

func newIPPortSerializer(c *model.IPPortContext) IPPortSerializer {
	return IPPortSerializer{
		IP:   c.IPNet.IP.String(),
		Port: c.Port,
	}
}

func newIPPortFamilySerializer(c *model.IPPortContext, family string) IPPortFamilySerializer {
	return IPPortFamilySerializer{
		IP:     c.IPNet.IP.String(),
		Port:   c.Port,
		Family: family,
	}
}

func newNetworkContextSerializer(e *model.Event) *NetworkContextSerializer {
	return &NetworkContextSerializer{
		Device:      newNetworkDeviceSerializer(e),
		L3Protocol:  model.L3Protocol(e.NetworkContext.L3Protocol).String(),
		L4Protocol:  model.L4Protocol(e.NetworkContext.L4Protocol).String(),
		Source:      newIPPortSerializer(&e.NetworkContext.Source),
		Destination: newIPPortSerializer(&e.NetworkContext.Destination),
		Size:        e.NetworkContext.Size,
	}
}

func newBindEventSerializer(e *model.Event) *BindEventSerializer {
	bes := &BindEventSerializer{
		Addr: newIPPortFamilySerializer(&e.Bind.Addr,
			model.AddressFamily(e.Bind.AddrFamily).String()),
	}
	return bes
}

func newSecurityProfileContextSerializer(e *model.SecurityProfileContext) *SecurityProfileContextSerializer {
	tags := make([]string, len(e.Tags))
	copy(tags, e.Tags)
	return &SecurityProfileContextSerializer{
		Name:    e.Name,
		Version: e.Version,
		Status:  e.Status.String(),
		Tags:    tags,
	}
}
