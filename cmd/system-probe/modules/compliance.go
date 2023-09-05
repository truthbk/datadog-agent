// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"
	"github.com/DataDog/datadog-agent/pkg/compliance"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"go.uber.org/atomic"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
)

// ComplianceModule is a system-probe module that exposes an HTTP api to
// perform compliance checks that require more privileges than security-agent
// can offer.
//
// For instance, being able to run cross-container checks at runtime by directly
// accessing the /proc/<pid>/root mount point.
var ComplianceModule = module.Factory{
	Name:             config.ComplianceModule,
	ConfigNamespaces: []string{},
	Fn: func(cfg *config.Config) (module.Module, error) {
		return &complianceModule{}, nil
	},
}

type complianceModule struct {
	performedChecks atomic.Uint64
}

// Close is a noop (implements module.Module)
func (*complianceModule) Close() {
}

// GetStats returns statistics related to the compliance module (implements module.Module)
func (m *complianceModule) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"performed_checks": m.performedChecks.Load(),
	}
}

// RegisterGRPC is a noop (implements module.Module)
func (*complianceModule) RegisterGRPC(grpc.ServiceRegistrar) error {
	return nil
}

// Register implements module.Module.
func (m *complianceModule) Register(router *module.Router) error {
	router.HandleFunc("/benchmark", utils.WithConcurrencyLimit(utils.DefaultMaxConcurrentRequests, m.handleBenchmark))
	return nil
}

func (m *complianceModule) handleError(writer http.ResponseWriter, request *http.Request, status int, err error) {
	_ = log.Errorf("Failed to properly handle %s request: %s", request.URL.Path, err)
	writer.WriteHeader(status)
}

func (m *complianceModule) handleBenchmark(writer http.ResponseWriter, request *http.Request) {
	m.performedChecks.Add(1)

	var req compliance.BenchmarkRequest
	d := json.NewDecoder(request.Body)
	defer request.Body.Close()
	if err := d.Decode(&req); err != nil {
		m.handleError(writer, request, http.StatusBadRequest, fmt.Errorf("could not read and unmarshal request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	benchmarkDir := filepath.Dir(req.BenchmarkFile)
	benchmarkName := filepath.Base(req.BenchmarkFile)
	benchmarks, err := compliance.LoadBenchmarks(benchmarkDir, benchmarkName, func(r *compliance.Rule) bool {
		return len(req.RuleIDs) == 0 || slices.Contains(req.RuleIDs, r.ID)
	})
	if err != nil || len(benchmarks) == 0 {
		m.handleError(writer, request, http.StatusNotFound,
			fmt.Errorf("could not find benchmark %q: %v", req.BenchmarkFile, err))
		return
	}

	resolver := compliance.NewResolver(ctx, compliance.ResolverOptions{
		Hostname:    req.Hostname,
		HostRoot:    req.HostRoot,
		HostRootPID: req.HostRootPID,
	})

	ruleThrottler := time.NewTicker(100 * time.Millisecond)
	defer ruleThrottler.Stop()

	var events []*compliance.CheckEvent
	for _, benchmark := range benchmarks {
		for _, rule := range benchmark.Rules {
			<-ruleThrottler.C
			results := compliance.ResolveAndEvaluateRegoRule(ctx, resolver, benchmark, rule)
			events = append(events, results...)
		}
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	e := json.NewEncoder(writer)
	if err := e.Encode(events); err != nil {
		_ = log.Errorf("Failed to properly handle %s request: could not send response %s", request.URL.Path, err)
	}
}
