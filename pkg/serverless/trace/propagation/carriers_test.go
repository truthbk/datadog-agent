package propagation

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func getMapFromCarrier(tm tracer.TextMapReader) map[string]string {
	if tm == nil {
		return nil
	}
	m := map[string]string{}
	tm.ForeachKey(func(key, val string) error {
		m[key] = val
		return nil
	})
	return m
}

func TestSQSMessageAttrCarrier(t *testing.T) {
	testcases := []struct {
		name     string
		attr     events.SQSMessageAttribute
		expMap   map[string]string
		expNoErr bool
	}{
		{
			name: "datadog-map",
			attr: events.SQSMessageAttribute{
				DataType: "String",
				StringValue: aws.String(`{
					"x-datadog-trace-id": "3754030949214830614",
					"x-datadog-parent-id": "9807017789787771839",
					"x-datadog-sampling-priority": "1",
					"x-datadog-tags": "_dd.p.dm=-0",
					"traceparent": "00-00000000000000003418ff4233c5c016-881986b8523c93bf-01",
					"tracestate": "dd=s:1;t.dm:-0"
				}`),
			},
			expMap: map[string]string{
				"x-datadog-trace-id":          "3754030949214830614",
				"x-datadog-parent-id":         "9807017789787771839",
				"x-datadog-sampling-priority": "1",
				"x-datadog-tags":              "_dd.p.dm=-0",
				"traceparent":                 "00-00000000000000003418ff4233c5c016-881986b8523c93bf-01",
				"tracestate":                  "dd=s:1;t.dm:-0",
			},
			expNoErr: true,
		},
		{
			name: "empty-map",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: aws.String("{}"),
			},
			expMap:   map[string]string{},
			expNoErr: true,
		},
		{
			name: "empty-string",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: aws.String(""),
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "nil-string",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: nil,
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "wrong-data-type",
			attr: events.SQSMessageAttribute{
				DataType: "Binary",
			},
			expMap:   nil,
			expNoErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := sqsMessageAttrCarrier(tc.attr)
			t.Logf("sqsMessageAttrCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expNoErr, err == nil)
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestSnsSqsMessageCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  events.SQSMessage
		expMap map[string]string
		expErr error
	}{
		{
			name: "empty-string-body",
			event: events.SQSMessage{
				Body: "",
			},
			expMap: nil,
			expErr: errors.New("Error unmarshaling message body: unexpected end of JSON input"),
		},
		{
			name: "empty-map-body",
			event: events.SQSMessage{
				Body: "{}",
			},
			expMap: nil,
			expErr: errors.New("No Datadog trace context found"),
		},
		{
			name: "no-msg-attrs",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {}
				}`,
			},
			expMap: nil,
			expErr: errors.New("No Datadog trace context found"),
		},
		{
			name: "wrong-type-msg-attrs",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": "attrs"
				}`,
			},
			expMap: nil,
			expErr: errors.New("Error unmarshaling message body: json: cannot unmarshal string into Go struct field .MessageAttributes of type map[string]struct { Type string; Value string }"),
		},
		{
			name: "non-binary-type",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "String",
							"Value": "Value"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: errors.New("Unsupported DataType in _datadog payload"),
		},
		{
			name: "cannot-decode",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "Value"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: errors.New("Error decoding binary: illegal base64 data at input byte 4"),
		},
		{
			name: "empty-string-encoded",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "` + base64.StdEncoding.EncodeToString([]byte(``)) + `"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: errors.New("Error unmarshaling the decoded binary: unexpected end of JSON input"),
		},
		{
			name: "empty-map-encoded",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "` + base64.StdEncoding.EncodeToString([]byte(`{}`)) + `"
						}
					}
				}`,
			},
			expMap: map[string]string{},
			expErr: nil,
		},
		{
			name: "datadog-map",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "` + base64.StdEncoding.EncodeToString([]byte(`{
								"x-datadog-trace-id": "3754030949214830614",
								"x-datadog-parent-id": "9807017789787771839",
								"x-datadog-sampling-priority": "1",
								"x-datadog-tags": "_dd.p.dm=-0",
								"traceparent": "00-00000000000000003418ff4233c5c016-881986b8523c93bf-01",
								"tracestate": "dd=s:1;t.dm:-0"
							}`)) + `"
						}
					}
				}`,
			},
			expMap: map[string]string{
				"x-datadog-trace-id":          "3754030949214830614",
				"x-datadog-parent-id":         "9807017789787771839",
				"x-datadog-sampling-priority": "1",
				"x-datadog-tags":              "_dd.p.dm=-0",
				"traceparent":                 "00-00000000000000003418ff4233c5c016-881986b8523c93bf-01",
				"tracestate":                  "dd=s:1;t.dm:-0",
			},
			expErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := snsSqsMessageCarrier(tc.event)
			t.Logf("snsSqsMessageCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr == nil, err == nil)
			if err != nil {
				assert.Equal(t, tc.expErr.Error(), err.Error())
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}
