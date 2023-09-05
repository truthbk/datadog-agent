// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/compliance"
	"github.com/stretchr/testify/require"
)

const fakeComplianceBench = `#
schema:
  version: 1.0.0
name: System-Probe-Test-Benchmark
framework: system-probe-test-benchmark
version: 1.2.3
rules:
  - id: system-probe-test-benchmark-1.2.3-1.1.1
    description:
    scope:
      - none
    input:
      - file:
          path: /etc/hosts
`

const fakeComplianceRego = ``

func TestComplianceCheckEndpoint(t *testing.T) {
	tmp := t.TempDir()
	{
		statusCode, _, respBody := doComplianceBenchmarkRequest(t, &compliance.BenchmarkRequest{
			Hostname:      "plop",
			HostRoot:      "/host/root",
			HostRootPID:   0,
			BenchmarkFile: "/idonotexist",
			RuleIDs:       nil,
		})
		require.Equal(t, http.StatusNotFound, statusCode)
		require.Len(t, respBody, 0)
	}

	{
		benchfile := filepath.Join(tmp, "system-probe-test-benchmark-1.2.3.yaml")
		rulefile := filepath.Join(tmp, "system-probe-test-benchmark-1.2.3-1.1.1.rego")
		err1 := os.WriteFile(benchfile, []byte(fakeComplianceBench), 0600)
		err2 := os.WriteFile(rulefile, []byte(fakeComplianceRego), 0600)
		require.NoError(t, err1, err2)

		statusCode, headers, respBody := doComplianceBenchmarkRequest(t, &compliance.BenchmarkRequest{
			Hostname:      "plop",
			HostRoot:      "/host/root",
			HostRootPID:   0,
			BenchmarkFile: benchfile,
			RuleIDs:       nil,
		})
		require.Equal(t, http.StatusOK, statusCode)
		require.Equal(t, "application/json", headers.Get("Content-Type"))

		var events []*compliance.CheckEvent
		err := json.Unmarshal(respBody, &events)
		require.NoError(t, err)
		require.Len(t, events, 1)
		event := events[0]
		require.Equal(t, compliance.CheckError, event.Result)
		require.Equal(t, "system-probe-test-benchmark-1.2.3-1.1.1", event.RuleID)
		require.Equal(t, compliance.RegoEvaluator, event.Evaluator)
		fmt.Printf("%s\n", event)
	}
}

func doComplianceBenchmarkRequest(t *testing.T, req *compliance.BenchmarkRequest) (int, http.Header, []byte) {
	rec := httptest.NewRecorder()
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	m := &complianceModule{}
	m.handleBenchmark(rec, httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(reqBytes)))

	response := rec.Result()

	defer response.Body.Close()
	resBytes, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, response.Header, resBytes
}
