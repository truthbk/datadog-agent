// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	trivyTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyReport "github.com/aquasecurity/trivy/pkg/types"
	"go.uber.org/atomic"

	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// SBOMSource defines is the default log source for the SBOM events
const SBOMSource = "runtime-security-agent"

type SBOM struct {
	sync.RWMutex
	trivyReport.Report

	Host             string
	Source           string
	Service          string
	Tags             []string
	ContainerID      string
	ReferenceCounter *atomic.Uint64

	sbomResolver    *SBOMResolver
	doNotSendBefore time.Time
	sent            bool
}

// resolveTags thread unsafe version of ResolveTags
func (s *SBOM) resolveTags() error {
	if len(s.Tags) >= 10 || len(s.ContainerID) == 0 {
		return nil
	}

	var err error
	s.Tags, err = s.sbomResolver.probe.resolvers.TagsResolver.ResolveWithErr(s.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", s.ContainerID, err)
	}
	return nil
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
	queuedWorkloadsInitCounters     map[string]*atomic.Uint64
	workloadAnalysisQueue           chan workloadAnalysisRequest

	// context tags and attributes
	hostname    string
	source      string
	contextTags []string
}

// NewSBOMResolver returns a new instance of SBOMResolver
func NewSBOMResolver(p *Probe) (*SBOMResolver, error) {
	resolver := &SBOMResolver{
		probe:                       p,
		workloads:                   make(map[string]*SBOM),
		queuedWorkloadsInitCounters: make(map[string]*atomic.Uint64),
		workloadAnalysisQueue:       make(chan workloadAnalysisRequest, 1000),
	}
	resolver.prepareContextTags()
	return resolver, nil
}

func (r *SBOMResolver) prepareContextTags() {
	// add hostname tag
	hostname, err := utils.GetHostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	r.hostname = hostname
	r.contextTags = append(r.contextTags, fmt.Sprintf("host:%s", r.hostname))

	// merge tags from config
	for _, tag := range coreconfig.GetConfiguredTags(true) {
		if strings.HasPrefix(tag, "host") {
			continue
		}
		r.contextTags = append(r.contextTags, tag)
	}

	// add source tag
	r.source = utils.GetTagValue("source", r.contextTags)
	if len(r.source) == 0 {
		r.source = SBOMSource
		r.contextTags = append(r.contextTags, fmt.Sprintf("source:%s", SBOMSource))
	}
}

// Start starts the goroutine of the SBOM resolver
func (r *SBOMResolver) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	senderTick := time.NewTimer(1 * time.Minute)
	defer senderTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-r.workloadAnalysisQueue:
			if err := r.analyzeWorkload(req); err != nil {
				seclog.Errorf("couldn't analyze workload [%s]: %v", req.containerID, err)
			}
		case <-senderTick.C:
			if err := r.SendAvailableSBOMs(); err != nil {
				seclog.Errorf("couldn't send SBOMs: %w", err)
			}
		}
	}
}

// generateSBOM calls Trivy to generate the SBOM of a workload
func (r *SBOMResolver) generateSBOM(root string, containerID string) (*SBOM, error) {
	// TODO: call "trivy fs" on "root"
	output := &SBOM{
		ReferenceCounter: atomic.NewUint64(0),
		Host:             r.hostname,
		Source:           r.source,
		ContainerID:      containerID,
		doNotSendBefore:  time.Now().Add(5 * time.Minute),
	}
	return output, nil
}

// analyzeWorkload generates the SBOM of the provided workload and send it to the security agent
func (r *SBOMResolver) analyzeWorkload(req workloadAnalysisRequest) error {
	sbom, err := r.generateSBOM(req.root, req.containerID)
	if err != nil {
		return err
	}

	// add reference counter value
	r.queuedWorkloadsInitCountersLock.Lock()
	defer r.queuedWorkloadsInitCountersLock.Unlock()
	counter, ok := r.queuedWorkloadsInitCounters[req.containerID]
	if ok {
		sbom.ReferenceCounter.Add(counter.Load())
	} else {
		sbom.ReferenceCounter.Add(1)
	}

	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()

	// check if a SBOM already exists to transfer reference counter values
	existingSBOM, ok := r.workloads[req.containerID]
	if ok {
		sbom.ReferenceCounter.Add(existingSBOM.ReferenceCounter.Load())
	}

	// replace existing SBOM with new one
	r.workloads[req.containerID] = sbom
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
	sbom, ok := r.workloads[containerID]
	r.workloadsLock.RUnlock()
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
		counter.Add(1)
		return
	}

	// queue analysis request
	r.queuedWorkloadsInitCounters[process.ContainerID] = atomic.NewUint64(1)
	req := workloadAnalysisRequest{
		containerID: process.ContainerID,
		root:        utils.ProcRootPath(int32(process.Pid)),
	}
	select {
	case r.workloadAnalysisQueue <- req:
	default:
	}
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
	// only delete sbom if it has already been sent, delay the deletion to the sender otherwise
	if counter <= 0 && sbom.sent {
		r.deleteSBOM(process.ContainerID)
	}
}

// deleteSBOM thread unsafe delete all data indexed by the provided container ID
func (r *SBOMResolver) deleteSBOM(containerID string) {
	// remove SBOM entry
	delete(r.workloads, containerID)
	// to be safe, delete the init counters as well
	delete(r.queuedWorkloadsInitCounters, containerID)
}

// AddContextTags Adds the tags resolved by the resolver to the provided SBOM
func (r *SBOMResolver) AddContextTags(s *SBOM) {
	var tagName string
	var found bool

	dumpTagNames := make([]string, 0, len(s.Tags))
	for _, tag := range s.Tags {
		dumpTagNames = append(dumpTagNames, utils.GetTagName(tag))
	}

	for _, tag := range r.contextTags {
		tagName = utils.GetTagName(tag)
		found = false

		for _, dumpTagName := range dumpTagNames {
			if tagName == dumpTagName {
				found = true
				break
			}
		}

		if !found {
			s.Tags = append(s.Tags, tag)
		}
	}
}

// SendAvailableSBOMs sends all SBOMs that are ready to be sent
func (r *SBOMResolver) SendAvailableSBOMs() error {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()
	now := time.Now()

	for _, sbom := range r.workloads {
		if err := r.processSBOM(sbom, now); err != nil {
			return err
		}
	}

	return nil
}

// processSBOM resolves the tags of the provided SBOM, send it and delete it when applicable
func (r *SBOMResolver) processSBOM(sbom *SBOM, now time.Time) error {
	sbom.Lock()
	defer sbom.Unlock()

	if !sbom.sent {
		// resolve tags
		_ = sbom.resolveTags()
	}

	if now.After(sbom.doNotSendBefore) {

		// check if we should send the SBOM now
		if !sbom.sent {
			r.AddContextTags(sbom)

			// resolve the service if it is defined
			sbom.Service = utils.GetTagValue("service", sbom.Tags)

			// send SBOM to the security agent
			sbomMsg, err := sbom.ToSBOMMessage()
			if err != nil {
				return fmt.Errorf("couldn't serialize SBOM to JSON: %w", err)
			}
			r.probe.DispatchSBOM(sbomMsg)
			sbom.sent = true
		}

		// check if we should delete the sbom
		if sbom.ReferenceCounter.Load() == 0 {
			r.deleteSBOM(sbom.ContainerID)
		}
	}
	return nil
}
