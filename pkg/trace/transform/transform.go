// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package transform implements mappings from OTLP to DD semantics, and helpers
package transform

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/collector/semconv/v1.6.1"

	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/trace"
	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/sampler"
	"github.com/DataDog/datadog-agent/pkg/trace/traceutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes"
)

// OperationAndResourceNameV2Enabled checks if the new operation and resource name logic should be used
func OperationAndResourceNameV2Enabled(conf *config.AgentConfig) bool {
	return !conf.OTLPReceiver.SpanNameAsResourceName && len(conf.OTLPReceiver.SpanNameRemappings) == 0 && conf.HasFeature("enable_operation_and_resource_name_logic_v2")
}

// OtelSpanToDDSpanMinimal otelSpanToDDSpan converts an OTel span to a DD span.
// The converted DD span only has the minimal number of fields for APM stats calculation and is only meant
// to be used in OTLPTracesToConcentratorInputs. Do not use them for other purposes.
func OtelSpanToDDSpanMinimal(
	otelspan ptrace.Span,
	otelres pcommon.Resource,
	lib pcommon.InstrumentationScope,
	isTopLevel, topLevelByKind bool,
	conf *config.AgentConfig,
	peerTagKeys []string,
) *pb.Span {
	var operationName string
	var resourceName string
	if OperationAndResourceNameV2Enabled(conf) {
		operationName = traceutil.GetOTelOperationNameV2(otelspan)
		resourceName = traceutil.GetOTelResourceV2(otelspan, otelres)
	} else {
		operationName = traceutil.GetOTelOperationNameV1(otelspan, otelres, lib, conf.OTLPReceiver.SpanNameAsResourceName, conf.OTLPReceiver.SpanNameRemappings, true)
		resourceName = traceutil.GetOTelResourceV1(otelspan, otelres)
	}

	// correct span type logic if using new resource receiver, keep same if on v1. separate from OperationAndResourceNameV2Enabled.
	var spanType string
	if conf.HasFeature("enable_receive_resource_spans_v2") {
		spanType = traceutil.GetOTelSpanType(otelspan, otelres)
	} else {
		spanType = traceutil.GetOTelAttrValInResAndSpanAttrs(otelspan, otelres, true, "span.type")
		if spanType == "" {
			spanType = traceutil.SpanKind2Type(otelspan, otelres)
		}
	}

	ddspan := &pb.Span{
		Service:  traceutil.GetOTelService(otelres, true),
		Name:     operationName,
		Resource: resourceName,
		TraceID:  traceutil.OTelTraceIDToUint64(otelspan.TraceID()),
		SpanID:   traceutil.OTelSpanIDToUint64(otelspan.SpanID()),
		ParentID: traceutil.OTelSpanIDToUint64(otelspan.ParentSpanID()),
		Start:    int64(otelspan.StartTimestamp()),
		Duration: int64(otelspan.EndTimestamp()) - int64(otelspan.StartTimestamp()),
		Type:     spanType,
		Meta:     make(map[string]string, otelres.Attributes().Len()+otelspan.Attributes().Len()),
		Metrics:  map[string]float64{},
	}
	spanKind := otelspan.Kind()
	ddspan.Meta["span.kind"] = traceutil.OTelSpanKindName(spanKind)
	code := traceutil.GetOTelStatusCode(otelspan)
	if code != 0 {
		ddspan.Metrics[traceutil.TagStatusCode] = float64(code)
	}
	if otelspan.Status().Code() == ptrace.StatusCodeError {
		ddspan.Error = 1
	}
	if isTopLevel {
		traceutil.SetTopLevel(ddspan, true)
	}
	if isMeasured := traceutil.GetOTelAttrVal(otelspan.Attributes(), false, "_dd.measured"); isMeasured == "1" {
		traceutil.SetMeasured(ddspan, true)
	} else if topLevelByKind && (spanKind == ptrace.SpanKindClient || spanKind == ptrace.SpanKindProducer) {
		// When enable_otlp_compute_top_level_by_span_kind is true, compute stats for client-side spans
		traceutil.SetMeasured(ddspan, true)
	}
	for _, peerTagKey := range peerTagKeys {
		if peerTagVal := traceutil.GetOTelAttrValInResAndSpanAttrs(otelspan, otelres, false, peerTagKey); peerTagVal != "" {
			ddspan.Meta[peerTagKey] = peerTagVal
		}
	}
	return ddspan
}

func isDatadogAPMConventionKey(k string) bool {
	return k == "service.name" || k == "operation.name" || k == "resource.name" || k == "span.type" || k == "http.method" || k == "http.status_code"
}

func setMetaOTLPWithHTTPMappings(k string, value string, ddspan *pb.Span) {
	datadogKey, found := attributes.HTTPMappings[k]
	switch {
	case found && value != "":
		ddspan.Meta[datadogKey] = value
	case strings.HasPrefix(k, "http.request.header."):
		key := fmt.Sprintf("http.request.headers.%s", strings.TrimPrefix(k, "http.request.header."))
		ddspan.Meta[key] = value
		// Exclude Datadog APM conventions.
		// These are handled above explicitly.
	case !isDatadogAPMConventionKey(k):
		SetMetaOTLP(ddspan, k, value)
	default:
		return
	}
}

// OtelSpanToDDSpan converts an OTel span to a DD span.
func OtelSpanToDDSpan(
	otelspan ptrace.Span,
	otelres pcommon.Resource,
	lib pcommon.InstrumentationScope,
	conf *config.AgentConfig,
	peerTagKeys []string,
) *pb.Span {
	spanKind := otelspan.Kind()
	topLevelByKind := conf.HasFeature("enable_otlp_compute_top_level_by_span_kind")
	isTopLevel := false
	if topLevelByKind {
		isTopLevel = otelspan.ParentSpanID() == pcommon.NewSpanIDEmpty() || spanKind == ptrace.SpanKindServer || spanKind == ptrace.SpanKindConsumer
	}
	ddspan := OtelSpanToDDSpanMinimal(otelspan, otelres, lib, isTopLevel, topLevelByKind, conf, peerTagKeys)

	otelres.Attributes().Range(func(k string, v pcommon.Value) bool {
		value := v.AsString()
		setMetaOTLPWithHTTPMappings(k, value, ddspan)
		return true
	})

	traceID := otelspan.TraceID()
	ddspan.Meta["otel.trace_id"] = hex.EncodeToString(traceID[:])
	if _, ok := ddspan.Meta["version"]; !ok {
		if serviceVersion, ok := otelres.Attributes().Get(semconv.AttributeServiceVersion); ok {
			ddspan.Meta["version"] = serviceVersion.AsString()
		}
	}

	if _, ok := ddspan.Meta["env"]; !ok {
		if env := traceutil.GetOTelEnv(otelres); env != "" {
			ddspan.Meta["env"] = env
		}
	}

	if otelspan.Events().Len() > 0 {
		ddspan.Meta["events"] = MarshalEvents(otelspan.Events())
	}
	TagSpanIfContainsExceptionEvent(otelspan, ddspan)
	if otelspan.Links().Len() > 0 {
		ddspan.Meta["_dd.span_links"] = MarshalLinks(otelspan.Links())
	}

	var gotMethodFromNewConv bool
	var gotStatusCodeFromNewConv bool

	otelspan.Attributes().Range(func(k string, v pcommon.Value) bool {
		value := v.AsString()
		switch v.Type() {
		case pcommon.ValueTypeDouble:
			SetMetricOTLP(ddspan, k, v.Double())
		case pcommon.ValueTypeInt:
			SetMetricOTLP(ddspan, k, float64(v.Int()))
		default:
			setMetaOTLPWithHTTPMappings(k, value, ddspan)
		}

		// `http.method` was renamed to `http.request.method` in the HTTP stabilization from v1.23.
		// See https://opentelemetry.io/docs/specs/semconv/http/migration-guide/#summary-of-changes
		// `http.method` is also the Datadog APM convention for the HTTP method.
		// We check both conventions and use the new one if it is present.
		// See https://datadoghq.atlassian.net/wiki/spaces/APM/pages/2357395856/Span+attributes#[inlineExtension]HTTP
		if k == "http.request.method" {
			gotMethodFromNewConv = true
		} else if k == "http.method" && !gotMethodFromNewConv {
			ddspan.Meta["http.method"] = value
		}

		// `http.status_code` was renamed to `http.response.status_code` in the HTTP stabilization from v1.23.
		// See https://opentelemetry.io/docs/specs/semconv/http/migration-guide/#summary-of-changes
		// `http.status_code` is also the Datadog APM convention for the HTTP status code.
		// We check both conventions and use the new one if it is present.
		// See https://datadoghq.atlassian.net/wiki/spaces/APM/pages/2357395856/Span+attributes#[inlineExtension]HTTP
		if k == "http.response.status_code" {
			gotStatusCodeFromNewConv = true
		} else if k == "http.status_code" && !gotStatusCodeFromNewConv {
			ddspan.Meta["http.status_code"] = value
		}

		return true
	})

	if otelspan.TraceState().AsRaw() != "" {
		ddspan.Meta["w3c.tracestate"] = otelspan.TraceState().AsRaw()
	}
	if lib.Name() != "" {
		ddspan.Meta[semconv.OtelLibraryName] = lib.Name()
	}
	if lib.Version() != "" {
		ddspan.Meta[semconv.OtelLibraryVersion] = lib.Version()
	}
	ddspan.Meta[semconv.OtelStatusCode] = otelspan.Status().Code().String()
	if msg := otelspan.Status().Message(); msg != "" {
		ddspan.Meta[semconv.OtelStatusDescription] = msg
	}
	Status2Error(otelspan.Status(), otelspan.Events(), ddspan)

	return ddspan
}

// TagSpanIfContainsExceptionEvent tags spans that contain at least on exception span event.
func TagSpanIfContainsExceptionEvent(otelspan ptrace.Span, ddspan *pb.Span) {
	for i := range otelspan.Events().Len() {
		if otelspan.Events().At(i).Name() == "exception" {
			ddspan.Meta["_dd.span_events.has_exception"] = "true"
			return
		}
	}
}

// MarshalEvents marshals events into JSON.
func MarshalEvents(events ptrace.SpanEventSlice) string {
	var str strings.Builder
	str.WriteString("[")
	for i := 0; i < events.Len(); i++ {
		e := events.At(i)
		if i > 0 {
			str.WriteString(",")
		}
		var wrote bool
		str.WriteString("{")
		if v := e.Timestamp(); v != 0 {
			str.WriteString(`"time_unix_nano":`)
			str.WriteString(strconv.FormatUint(uint64(v), 10))
			wrote = true
		}
		if v := e.Name(); v != "" {
			if wrote {
				str.WriteString(",")
			}
			str.WriteString(`"name":`)
			if name, err := json.Marshal(v); err == nil {
				str.WriteString(string(name))
			} else {
				// still collect the event information, if possible
				log.Errorf("Error parsing span event name %v, using name 'redacted' instead", name)
				str.WriteString(`"redacted"`)
			}
			wrote = true
		}
		if e.Attributes().Len() > 0 {
			if wrote {
				str.WriteString(",")
			}
			str.WriteString(`"attributes":{`)
			j := 0
			e.Attributes().Range(func(k string, v pcommon.Value) bool {
				// collect the attribute only if the key is json-parseable, else drop the attribute
				if key, err := json.Marshal(k); err == nil {
					if j > 0 {
						str.WriteString(",")
					}
					str.WriteString(string(key))
					str.WriteString(":")
					if val, err := json.Marshal(v.AsRaw()); err == nil {
						str.WriteString(string(val))
					} else {
						log.Warnf("Trouble parsing the following attribute value, dropping: %v", v.AsString())
						str.WriteString(`"redacted"`)
					}
					j++
				} else {
					log.Errorf("Error parsing the following attribute key on span event %v, dropping attribute: %v", e.Name(), k)
					e.SetDroppedAttributesCount(e.DroppedAttributesCount() + 1)
				}
				j++
				return true
			})
			str.WriteString("}")
			wrote = true
		}
		if v := e.DroppedAttributesCount(); v != 0 {
			if wrote {
				str.WriteString(",")
			}
			str.WriteString(`"dropped_attributes_count":`)
			str.WriteString(strconv.FormatUint(uint64(v), 10))
		}
		str.WriteString("}")
	}
	str.WriteString("]")
	return str.String()
}

// MarshalLinks marshals span links into JSON.
func MarshalLinks(links ptrace.SpanLinkSlice) string {
	var str strings.Builder
	str.WriteString("[")
	for i := 0; i < links.Len(); i++ {
		l := links.At(i)
		if i > 0 {
			str.WriteString(",")
		}
		t := l.TraceID()
		str.WriteString(`{"trace_id":"`)
		str.WriteString(hex.EncodeToString(t[:]))
		s := l.SpanID()
		str.WriteString(`","span_id":"`)
		str.WriteString(hex.EncodeToString(s[:]))
		str.WriteString(`"`)
		if ts := l.TraceState().AsRaw(); len(ts) > 0 {
			str.WriteString(`,"trace_state":"`)
			str.WriteString(ts)
			str.WriteString(`"`)
		}
		if l.Attributes().Len() > 0 {
			str.WriteString(`,"attributes":{`)
			var b bool
			l.Attributes().Range(func(k string, v pcommon.Value) bool {
				if b {
					str.WriteString(",")
				}
				b = true
				str.WriteString(`"`)
				str.WriteString(k)
				str.WriteString(`":"`)
				str.WriteString(v.AsString())
				str.WriteString(`"`)
				return true
			})
			str.WriteString("}")
		}
		if l.DroppedAttributesCount() > 0 {
			str.WriteString(`,"dropped_attributes_count":`)
			str.WriteString(strconv.FormatUint(uint64(l.DroppedAttributesCount()), 10))
		}
		str.WriteString("}")
	}
	str.WriteString("]")
	return str.String()
}

// SetMetaOTLP sets the k/v OTLP attribute pair as a tag on span s.
func SetMetaOTLP(s *pb.Span, k, v string) {
	switch k {
	case "operation.name":
		s.Name = v
	case "service.name":
		s.Service = v
	case "resource.name":
		s.Resource = v
	case "span.type":
		s.Type = v
	case "analytics.event":
		if v, err := strconv.ParseBool(v); err == nil {
			if v {
				s.Metrics[sampler.KeySamplingRateEventExtraction] = 1
			} else {
				s.Metrics[sampler.KeySamplingRateEventExtraction] = 0
			}
		}
	default:
		s.Meta[k] = v
	}
}

// SetMetricOTLP sets the k/v OTLP attribute pair as a metric on span s.
func SetMetricOTLP(s *pb.Span, k string, v float64) {
	switch k {
	case "sampling.priority":
		s.Metrics["_sampling_priority_v1"] = v
	default:
		s.Metrics[k] = v
	}
}

// Status2Error checks the given status and events and applies any potential error and messages
// to the given span attributes.
func Status2Error(status ptrace.Status, events ptrace.SpanEventSlice, span *pb.Span) {
	if status.Code() != ptrace.StatusCodeError {
		return
	}
	span.Error = 1
	for i := 0; i < events.Len(); i++ {
		e := events.At(i)
		if strings.ToLower(e.Name()) != "exception" {
			continue
		}
		attrs := e.Attributes()
		if v, ok := attrs.Get(semconv.AttributeExceptionMessage); ok {
			span.Meta["error.msg"] = v.AsString()
		}
		if v, ok := attrs.Get(semconv.AttributeExceptionType); ok {
			span.Meta["error.type"] = v.AsString()
		}
		if v, ok := attrs.Get(semconv.AttributeExceptionStacktrace); ok {
			span.Meta["error.stack"] = v.AsString()
		}
	}
	if _, ok := span.Meta["error.msg"]; !ok {
		// no error message was extracted, find alternatives
		if status.Message() != "" {
			// use the status message
			span.Meta["error.msg"] = status.Message()
		} else if _, httpcode := GetFirstFromMap(span.Meta, "http.response.status_code", "http.status_code"); httpcode != "" {
			// `http.status_code` was renamed to `http.response.status_code` in the HTTP stabilization from v1.23.
			// See https://opentelemetry.io/docs/specs/semconv/http/migration-guide/#summary-of-changes

			// http.status_text was removed in spec v0.7.0 (https://github.com/open-telemetry/opentelemetry-specification/pull/972)
			// TODO (OTEL-1791) Remove this and use a map from status code to status text.
			if httptext, ok := span.Meta["http.status_text"]; ok {
				span.Meta["error.msg"] = fmt.Sprintf("%s %s", httpcode, httptext)
			} else {
				span.Meta["error.msg"] = httpcode
			}
		}
	}
}

// GetFirstFromMap checks each key in the given keys in the map and returns the first key-value pair whose
// key matches, or empty strings if none matches.
func GetFirstFromMap(m map[string]string, keys ...string) (string, string) {
	for _, key := range keys {
		if val := m[key]; val != "" {
			return key, val
		}
	}
	return "", ""
}
