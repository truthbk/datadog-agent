//go:generate go run github.com/mailru/easyjson/easyjson -gen_build_flags=-mod=mod -no_std_marshalers -build_tags linux $GOFILE
//go:generate go run github.com/DataDog/datadog-agent/pkg/security/probe/doc_generator -output ../../../docs/cloud-workload-security/backend.schema.json

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package serializers

import (
	jwriter "github.com/mailru/easyjson/jwriter"

	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// EventContextSerializer serializes an event context to JSON
// easyjson:json
type EventContextSerializer struct {
	// Event name
	Name string `json:"name,omitempty"`
	// Event category
	Category string `json:"category,omitempty"`
}

// EventSerializer serializes an event to JSON
// easyjson:json
type EventSerializer struct {
	EventContextSerializer                  `json:"evt,omitempty"`
	Date                                    utils.EasyjsonTime `json:"date,omitempty"`
}

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

// NewEventSerializer creates a new event serializer based on the event type
func NewEventSerializer(event *model.Event, resolvers *resolvers.Resolvers) *EventSerializer {
	s := &EventSerializer{
		EventContextSerializer: EventContextSerializer{
			Name:  model.EventType(event.Type).String(),
		},
		Date:                     utils.NewEasyjsonTime(event.FieldHandlers.ResolveEventTime(event)),
	}

	eventType := model.EventType(event.Type)

	s.Category = model.GetEventTypeCategory(eventType.String())

	switch eventType {
	case model.ExitEventType:
		/*s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.ProcessContext.Process.FileEvent, event),
		}
		s.ExitEventSerializer = newExitEventSerializer(event)*/
	case model.ExecEventType:
		/*s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.ProcessContext.Process.FileEvent, event),
		}*/
	}

	return s
}