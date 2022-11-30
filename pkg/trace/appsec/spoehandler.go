// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package appsec

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/trace/appsec/spoe"
	"github.com/DataDog/datadog-agent/pkg/trace/log"
	waf "github.com/DataDog/go-libddwaf"
)

type SpanMap struct {
	sync.Mutex
	spans map[string]httpSpan
}

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
		log.Infof("Unknown: %v", i)
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

func parseHeaders(input string) map[string]string {
	var result = make(map[string]string)

	headerLines := strings.Split(input, "\n")

	for _, line := range headerLines {
		headerElments := strings.SplitAfterN(line, ":", 2)
		if len(headerElments) > 1 {
			result[strings.TrimRight(headerElments[0], ":")] = strings.TrimRight(strings.TrimLeft(headerElments[1], " "), "\r\n")
		}
	}

	return result
}

func NewSpoeSecHandler(handle *waf.Handle, traceChan chan *api.Payload) func(messages *spoe.MessageIterator) ([]spoe.Action, error) {

	var currentSpanMap = SpanMap{
		sync.Mutex{},
		make(map[string]httpSpan),
	}

	return func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
		reputation := 0

		for messages.Next() {
			msg := messages.Message

			log.Infof("spoe message: %s", msg.Name)

			if msg.Name == "frontend_http_request" {
				var id string
				var service = "an-haproxy"
				var remoteAddr string
				var version string
				var method string
				var urlTemp string
				var url *url.URL
				var headers map[string]string

				var err error
				for msg.Args.Next() {
					arg := msg.Args.Arg

					log.Infof("arg.Name: %s", arg.Name)
					printInterface(arg.Value)

					switch arg.Name {
					case "id":
						id = arg.Value.(string)
					case "http.method":
						method = arg.Value.(string)
					case "http.version":
						version = arg.Value.(string)
					case "http.url":
						urlTemp = "/toto" // arg.Value.(string)
						log.Infof("urlTemp %s", urlTemp)
					case "http.headers":
						headers = parseHeaders(arg.Value.(string))
					}
				}

				urlFake := fmt.Sprintf("http://%s%s", headers["host"], urlTemp)
				url, err = url.Parse(urlFake)
				log.Info("done url.Parse")
				if err != nil {
					log.Errorf("Error parsing url %s, err = %s", urlFake, err.Error())
					continue
				}

				sp := startHTTPRequestSpan(0, 0, service, remoteAddr, method, url, headers)
				sp.Meta["http.version"] = version

				currentSpanMap.Lock()
				currentSpanMap.spans[id] = sp
				currentSpanMap.Unlock()

				defer func() {
					sp.finish()
					sendSpan(sp.Span, int32(1), traceChan)
					log.Infof("sent span for: %s", url)
				}()
			}
			if msg.Name == "http_response" {
				var id string
				var status int
				for msg.Args.Next() {
					arg := msg.Args.Arg

					log.Infof("arg.Name: %s", arg.Name)
					printInterface(arg.Value)

					switch arg.Name {
					case "id":
						id = arg.Value.(string)
					case "http.status_code":
						status = arg.Value.(int)
					}
				}

				var sp httpSpan
				currentSpanMap.Lock()
				sp = currentSpanMap.spans[id]
				delete(currentSpanMap.spans, id)
				currentSpanMap.Unlock()

				sp.Meta["http.status"] = strconv.Itoa(status)
				sp.finish()

				defer func() {
					sendSpan(sp.Span, int32(1), traceChan)
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
