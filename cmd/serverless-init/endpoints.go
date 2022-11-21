package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/serverless/metrics"
	"github.com/DataDog/datadog-agent/pkg/serverless/trace"
)

const serverAddr = ":8127"

var ready = struct {
	sync.Mutex
	areYou bool
	done   chan struct{}
}{done: make(chan struct{}, 1)}

func waitTillReady(timeout time.Duration) bool {
	ready.Lock()
	defer ready.Unlock()
	if ready.areYou {
		return true
	}
	select {
	case <-ready.done:
		ready.areYou = true
	case <-time.After(timeout):
	}
	return ready.areYou
}

func setupEndpoints(traceAgent *trace.ServerlessTraceAgent, metricAgent *metrics.ServerlessMetricAgent) {
	mux := http.NewServeMux()
	mux.Handle("/trace/flush", newFlushHandler(traceAgent))
	mux.Handle("/metrics/flush", newFlushHandler(metricAgent))
	mux.HandleFunc("/ready", readyHandler)
	go log.Fatal(http.ListenAndServe(serverAddr, mux))
	ready.done <- struct{}{}
}

type flusher interface {
	Flush()
}

func newFlushHandler(agent flusher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		agent.Flush()
		w.WriteHeader(http.StatusOK)
	})
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch waitTillReady(5 * time.Second) {
	case true:
		w.Write([]byte(`{"ready":"true"}`))
	case false:
		w.Write([]byte(`{"ready":"false"}`))
	}
}
