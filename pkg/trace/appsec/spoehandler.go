// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package appsec

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/trace/appsec/spoe"
	"github.com/DataDog/datadog-agent/pkg/trace/log"
	waf "github.com/DataDog/go-libddwaf"
)

func printInterface(i interface{}) {
	switch i.(type) { // the switch uses the type of the interface
	case int32:
		log.Infof("int32: %s", i.(int32))
	case int64:
		log.Infof("int64: %s", i.(int64))
	case float32:
		log.Infof("float32: %s", i.(float32))
	case float64:
		log.Infof("float64: %s", i.(float64))
	case string:
		log.Infof("string: %s", i.(string))
	default:
		log.Info("Unknown")
	}
}

func argToString(input interface{}) (string, error) {
	var result string
	var ok bool
	result, ok = input.(string)
	if !ok {
		return "", fmt.Errorf("spoe handler: expected url in message, got %+v", result)
	}
	return result, nil
}

func NewSpoeSecHandler(handle *waf.Handle, traceChan chan *api.Payload) func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
	return func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
		reputation := 0

		for messages.Next() {
			msg := messages.Message

			log.Infof("spoe message: %s", msg.Name)

			if msg.Name == "frontend_http_request" {
				sp := startHTTPRequestSpan(0, 0, "", "")

				var url string
				for msg.Args.Next() {
					arg := msg.Args.Arg

					log.Infof("arg.Name: %s", arg.Name)
					printInterface(arg.Value)

					switch arg.Name {
					case "http.method":
						sp.Meta[arg.Name] = arg.Value.(string)
					case "http.version":
						sp.Meta[arg.Name] = arg.Value.(string)
					case "http.url":
						// TODO parse out the resouce name
						sp.Resource = arg.Value.(string)
						sp.Meta[arg.Name] = arg.Value.(string)
					case "http.headers":
						log.Infof("TODO parse headers")
					}
				}

				log.Infof("opentracing:frontend_http_request for: %s", url)
				sp.Meta["appsec.event"] = "true"
				defer func() {
					sp.finish()
					sendSpan(sp.Span, int32(1), traceChan)
					log.Infof("sent span for: %s", url)
				}()
			}
		}

		return []spoe.Action{
			spoe.ActionSetVar{
				Name:  "reputation",
				Scope: spoe.VarScopeSession,
				Value: reputation,
			},
		}, nil
	}
}
