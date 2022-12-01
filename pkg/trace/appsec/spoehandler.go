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

type spanInfo struct {
	span    httpSpan
	headers map[string]string
	url     *url.URL
}

type spanMap struct {
	sync.Mutex
	spans map[string]spanInfo
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

func makeHTTPSecAddressesOfHeaderMap(requestHeaders map[string]string, method string, url *url.URL, clientIP string, status string) map[string]interface{} {
	headers := map[string]string{}
	for h, v := range requestHeaders {
		h = strings.ToLower(h)
		if h == "cookie" {
			continue
		}
		headers[h] = v
	}
	addr := map[string]interface{}{
		"server.request.method":             method,
		"server.request.headers.no_cookies": headers,
		"server.request.uri.raw":            url.RequestURI(),
		"server.request.query":              url.Query(),
		"server.response.status":            status,
	}
	if clientIP != "" {
		addr["http.client_ip"] = clientIP
	}
	return addr
}

func NewSpoeSecHandler(handle *waf.Handle, traceChan chan *api.Payload) func(messages *spoe.MessageIterator) ([]spoe.Action, error) {

	var currentSpanMap = spanMap{
		sync.Mutex{},
		make(map[string]spanInfo),
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
				currentSpanMap.spans[id] = spanInfo{sp, headers, url}
				currentSpanMap.Unlock()
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

				var si spanInfo
				currentSpanMap.Lock()
				si = currentSpanMap.spans[id]
				delete(currentSpanMap.spans, id)
				currentSpanMap.Unlock()

				sp := si.span

				statusString := strconv.Itoa(status)
				sp.Meta["http.status"] = statusString

				defer func() {
					sp.finish()
					sendSpan(sp.Span, int32(1), traceChan)
				}()

				wafCtx := waf.NewContext(handle)
				if wafCtx == nil {
					// The WAF handle got released in the meantime
					// writeUnavailableResponse(w)
					continue
				}
				defer wafCtx.Close()

				addresses := makeHTTPSecAddressesOfHeaderMap(si.headers, sp.Meta["http.method"], si.url, sp.Meta["http.client_ip"], statusString)
				log.Debug("appsec: httpsec api: running the security rules against %v", addresses)
				matches, actions, err := wafCtx.Run(addresses, defaultWAFTimeout)
				if err != nil && err != waf.ErrTimeout {
					log.Errorf("Error running waf: %v", err)
					continue
				}
				log.Infof("appsec: httpsec api: matches=%s actions=%v", string(matches), actions)

				if len(matches) > 0 {
					setSecurityEventsTags(sp, matches, si.headers, nil)
				}
				if len(actions) > 0 {
					sp.Meta["blocked"] = "true"
				}
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
