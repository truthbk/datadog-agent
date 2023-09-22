package propagation

import (
	"encoding/base64"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestNilExtractor(t *testing.T) {
	var extractor *Extractor
	tc, err := extractor.Extract("hello world")
	t.Logf("Extract returned TraceContext=%#v error=%#v", tc, err)
	assert.Equal(t, "Extraction not configured", err.Error())
	assert.Nil(t, tc)
}

func TestExtractorExtract(t *testing.T) {
	type propID struct {
		asUint uint64
		asStr  string
	}
	ddTraceID := propID{3754030949214830614, "3754030949214830614"}
	ddSpanID := propID{9807017789787771839, "9807017789787771839"}
	w3cTraceID := propID{3754030949214781440, "3418ff4233c50000"}
	w3cSpanID := propID{9807017789787734016, "881986b8523c0000"}

	testcases := []struct {
		name     string
		extType  string
		event    interface{}
		expCtx   *TraceContext
		expNoErr bool
	}{
		{
			name:     "string-event",
			event:    "hello world",
			expCtx:   nil,
			expNoErr: false,
		},
		{
			name: "get-reader-error",
			event: events.SQSMessage{
				Body: "",
			},
			expCtx:   nil,
			expNoErr: false,
		},
		{
			name: "extract-error",
			event: events.SQSMessage{
				MessageAttributes: map[string]events.SQSMessageAttribute{
					"_datadog": events.SQSMessageAttribute{
						DataType:    "String",
						StringValue: aws.String("{}"),
					},
				},
			},
			expCtx:   nil,
			expNoErr: false,
		},
		{
			name:    "extract-sqs-datadog-headers",
			extType: "datadog",
			event: events.SQSMessage{
				MessageAttributes: map[string]events.SQSMessageAttribute{
					"_datadog": events.SQSMessageAttribute{
						DataType: "String",
						StringValue: aws.String(`{
							"x-datadog-trace-id": "` + ddTraceID.asStr + `",
							"x-datadog-parent-id": "` + ddSpanID.asStr + `",
							"x-datadog-sampling-priority": "1",
							"x-datadog-tags": "_dd.p.dm=-0",
							"traceparent": "00-0000000000000000` + w3cTraceID.asStr + "-" + w3cSpanID.asStr + `-01",
							"tracestate": "dd=s:1;t.dm:-0"
						}`),
					},
				},
			},
			expCtx: &TraceContext{
				TraceID:  ddTraceID.asUint,
				ParentID: ddSpanID.asUint,
			},
			expNoErr: true,
		},
		{
			name:    "extract-snssqs-datadog-headers",
			extType: "datadog",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "` + base64.StdEncoding.EncodeToString([]byte(`{
								"x-datadog-trace-id": "`+ddTraceID.asStr+`",
								"x-datadog-parent-id": "`+ddSpanID.asStr+`",
								"x-datadog-sampling-priority": "1",
								"x-datadog-tags": "_dd.p.dm=-0",
								"traceparent": "00-0000000000000000`+w3cTraceID.asStr+"-"+w3cSpanID.asStr+`-01",
								"tracestate": "dd=s:1;t.dm:-0"
							}`)) + `"
						}
					}
				}`,
			},
			expCtx: &TraceContext{
				TraceID:  ddTraceID.asUint,
				ParentID: ddSpanID.asUint,
			},
			expNoErr: true,
		},
		{
			name:    "extract-sqs-tracecontext-headers",
			extType: "tracecontext",
			event: events.SQSMessage{
				MessageAttributes: map[string]events.SQSMessageAttribute{
					"_datadog": events.SQSMessageAttribute{
						DataType: "String",
						StringValue: aws.String(`{
							"x-datadog-trace-id": "` + ddTraceID.asStr + `",
							"x-datadog-parent-id": "` + ddSpanID.asStr + `",
							"x-datadog-sampling-priority": "1",
							"x-datadog-tags": "_dd.p.dm=-0",
							"traceparent": "00-0000000000000000` + w3cTraceID.asStr + "-" + w3cSpanID.asStr + `-01",
							"tracestate": "dd=s:1;t.dm:-0"
						}`),
					},
				},
			},
			expCtx: &TraceContext{
				TraceID:  w3cTraceID.asUint,
				ParentID: w3cSpanID.asUint,
			},
			expNoErr: true,
		},
		{
			// XXX: This is surprising
			// The go tracer is designed to always place the tracecontext propagator first
			// see https://github.com/DataDog/dd-trace-go/blob/6a938b3b4054ce036cc60147ab42a86f743fcdd5/ddtrace/tracer/textmap.go#L231
			name:    "datadog,tracecontext-uses-tracecontext",
			extType: "datadog,tracecontext",
			event: events.SQSMessage{
				MessageAttributes: map[string]events.SQSMessageAttribute{
					"_datadog": events.SQSMessageAttribute{
						DataType: "String",
						StringValue: aws.String(`{
							"x-datadog-trace-id": "` + ddTraceID.asStr + `",
							"x-datadog-parent-id": "` + ddSpanID.asStr + `",
							"x-datadog-sampling-priority": "1",
							"x-datadog-tags": "_dd.p.dm=-0",
							"traceparent": "00-0000000000000000` + w3cTraceID.asStr + "-" + w3cSpanID.asStr + `-01",
							"tracestate": "dd=s:1;t.dm:-0"
						}`),
					},
				},
			},
			expCtx: &TraceContext{
				TraceID:  w3cTraceID.asUint,
				ParentID: w3cSpanID.asUint,
			},
			expNoErr: true,
		},
		{
			name:    "extract-sqs-tracecontext,datadog-headers",
			extType: "tracecontext,datadog",
			event: events.SQSMessage{
				MessageAttributes: map[string]events.SQSMessageAttribute{
					"_datadog": events.SQSMessageAttribute{
						DataType: "String",
						StringValue: aws.String(`{
							"x-datadog-trace-id": "` + ddTraceID.asStr + `",
							"x-datadog-parent-id": "` + ddSpanID.asStr + `",
							"x-datadog-sampling-priority": "1",
							"x-datadog-tags": "_dd.p.dm=-0",
							"traceparent": "00-0000000000000000` + w3cTraceID.asStr + "-" + w3cSpanID.asStr + `-01",
							"tracestate": "dd=s:1;t.dm:-0"
						}`),
					},
				},
			},
			expCtx: &TraceContext{
				TraceID:  w3cTraceID.asUint,
				ParentID: w3cSpanID.asUint,
			},
			expNoErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DD_TRACE_PROPAGATION_STYLE", tc.extType)
			extractor := NewExtractor()
			ctx, err := extractor.Extract(tc.event)
			t.Logf("Extract returned TraceContext=%#v error=%#v", ctx, err)
			assert.Equal(t, tc.expNoErr, err == nil)
			assert.Equal(t, tc.expCtx, ctx)
		})
	}
}
