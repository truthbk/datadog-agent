// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	trivyTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyReport "github.com/aquasecurity/trivy/pkg/types"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/security/api"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

type SBOM struct {
	sync.RWMutex
	trivyReport.Report

	ReferenceCounter *atomic.Uint64
	ReportReady      bool
}

// ToSBOMMessage returns an *api.SBOMMessage instance from an SBOM instance
func (s *SBOM) ToSBOMMessage() (*api.SBOMMessage, error) {
	// TODO add image & version name in SBOMMessage
	data, err := json.Marshal(s)
	if err == nil {
		return &api.SBOMMessage{Data: data}, nil
	}
	return nil, err
}

type workloadAnalysisRequest struct {
	containerID string
	root        string
	initCounter uint64
}

// SBOMResolver is the Software Bill-Of-material resolver
type SBOMResolver struct {
	workloadsLock sync.RWMutex
	workloads     map[string]*SBOM
	probe         *Probe

	// Queued workload analysis
	queuedWorkloadsInitCountersLock sync.RWMutex
	queuedWorkloadsInitCounters     map[string]int
	workloadAnalysisQueue           chan workloadAnalysisRequest
}

// NewSBOMResolver returns a new instance of SBOMResolver
func NewSBOMResolver(p *Probe) (*SBOMResolver, error) {
	resolver := &SBOMResolver{
		probe:                       p,
		workloads:                   make(map[string]*SBOM),
		queuedWorkloadsInitCounters: make(map[string]int),
		workloadAnalysisQueue:       make(chan workloadAnalysisRequest),
	}
	return resolver, nil
}

// Start starts the goroutine of the SBOM resolver
func (r *SBOMResolver) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-r.workloadAnalysisQueue:
			if err := r.analyzeWorkload(req); err != nil {
				seclog.Errorf("couldn't analyze workload [%s]: %v", req.containerID, err)
			}
		}
	}
}

// generateSBOM calls Trivy to generate the SBOM of a workload
func (r *SBOMResolver) generateSBOM(root string) (*SBOM, error) {
	// TODO: call "trivy fs" on "root"
	output := &SBOM{
		ReferenceCounter: atomic.NewUint64(1),
	}
	return output, nil
}

// analyzeWorkload generates the SBOM of the provided workload and send it to the security agent
func (r *SBOMResolver) analyzeWorkload(req workloadAnalysisRequest) error {
	sbom, err := r.generateSBOM(req.root)
	if err != nil {
		return err
	}

	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()
	r.workloads[req.containerID] = sbom

	// send SBOM to the security agent
	sbomMsg, err := sbom.ToSBOMMessage()
	if err != nil {
		return fmt.Errorf("couldn't serialize SBOM to JSON: %w", err)
	}
	r.probe.DispatchSBOM(sbomMsg)
	return nil
}

// RefreshSBOM analyzes the file system of a workload to refresh its SBOM.
func (r *SBOMResolver) RefreshSBOM(process *model.ProcessCacheEntry) {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()
	r.queueWorkloadAnalysis(process)
}

// ResolvePackage returns the Package that owns the provided file. Make sure the internal fields of "file" are properly
// resolved.
func (r *SBOMResolver) ResolvePackage(containerID string, file *model.FileEvent) *trivyTypes.Package {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()

	sbom, ok := r.workloads[containerID]
	if !ok {
		return nil
	}

	sbom.RLock()
	defer sbom.RUnlock()
	// Look for the provided file in all the packages of the workload
	for _, result := range sbom.Results {
		for _, pkg := range result.Packages {
			// TODO iterate over the list of files in the package
			if pkg.FilePath == file.PathnameStr {
				return &pkg
			}
		}
	}
	return nil
}

// queueWorkloadAnalysis (thread unsafe) queues a workload for analysis or increment the reference counter of the
// SBOM of a queued analysis.
func (r *SBOMResolver) queueWorkloadAnalysis(process *model.ProcessCacheEntry) {
	// check if this workload is already queued
	r.queuedWorkloadsInitCountersLock.Lock()
	defer r.queuedWorkloadsInitCountersLock.Unlock()

	counter, ok := r.queuedWorkloadsInitCounters[process.ContainerID]
	if ok {
		counter += 1
		return
	}

	// queue analysis request
	r.queuedWorkloadsInitCounters[process.ContainerID] = 1
	req := workloadAnalysisRequest{
		containerID: process.ContainerID,
		root:        utils.ProcRootPath(int32(process.Pid)),
	}
	r.workloadAnalysisQueue <- req
	return
}

// Retain increments the reference counter of the SBOM of a workload
func (r *SBOMResolver) Retain(process *model.ProcessCacheEntry) {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()

	sbom, ok := r.workloads[process.ContainerID]
	if !ok {
		r.queueWorkloadAnalysis(process)
		return
	}

	sbom.Lock()
	defer sbom.Unlock()
	sbom.ReferenceCounter.Add(1)
	return
}

// Release decrements the reference counter of the SBOM of a workload
func (r *SBOMResolver) Release(process *model.ProcessCacheEntry) {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()

	sbom, ok := r.workloads[process.ContainerID]
	if !ok {
		return
	}

	sbom.Lock()
	defer sbom.Unlock()
	counter := sbom.ReferenceCounter.Sub(1)
	if counter <= 0 {
		// remove SBOM entry
		delete(r.workloads, process.ContainerID)
	}
}
