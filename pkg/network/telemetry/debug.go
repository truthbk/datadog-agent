package telemetry

import (
	"encoding/json"
	"net/http"
)

var debugDelta deltaCalculator

// DebugHandler implements a route handler that serves a debug summary of
// all telemetry registered via this library.
func DebugHandler(w http.ResponseWriter, _ *http.Request) {
	type metric struct {
		Name string
		Tags []string `json:",omitempty"`
		Opts []string

		// Used for non-monotonic metrics
		Value int64 `json:",omitempty"`

		// Used for monotonic metrics
		DeltaValue     int64 `json:",omitempty"`
		MonotonicValue int64 `json:",omitempty"`
	}

	metrics := GetMetrics()
	previousValues := debugDelta.GetState("")
	debugData := make([]metric, 0, len(metrics))
	for _, m := range metrics {
		debugInfo := metric{
			Name: m.name,
			Tags: m.tags,
			Opts: m.opts,
		}

		if contains(OptMonotonic, m.opts) {
			debugInfo.DeltaValue = previousValues.ValueFor(m)
			debugInfo.MonotonicValue = m.Get()
		} else {
			debugInfo.Value = m.Get()
		}

		debugData = append(debugData, debugInfo)
	}

	jsonData, err := json.MarshalIndent(debugData, "", "    ")
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Write(jsonData)
}
