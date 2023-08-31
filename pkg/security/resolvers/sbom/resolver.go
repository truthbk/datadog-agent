// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && trivy

package sbom

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.uber.org/atomic"

	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	configUtils "github.com/DataDog/datadog-agent/pkg/config/utils"
	sbompkg "github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/sbom/collectors/host"
	sbomscanner "github.com/DataDog/datadog-agent/pkg/sbom/scanner"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/trivy"
)

// SBOMSource defines is the default log source for the SBOM events
const SBOMSource = "runtime-security-agent"

const maxSBOMGenerationRetries = 3

type sbomPackageFiles map[string]*Package

type workloadEntry struct {
	containerID string
	cgroup      *cgroupModel.CacheEntry
	key         string
}

func newWorkloadEntry(containerID string, cgroup *cgroupModel.CacheEntry) *workloadEntry {
	key := cgroup.WorkloadSelector.Image + ":" + cgroup.WorkloadSelector.Tag
	return &workloadEntry{
		containerID: containerID,
		cgroup:      cgroup,
		key:         key,
	}
}

// Resolver is the Software Bill-Of-material resolver
type Resolver struct {
	workloadsLock sync.RWMutex
	workloads     map[string]*workloadEntry

	sbomsCacheLock sync.RWMutex
	sbomsCache     *simplelru.LRU[string, sbomPackageFiles]

	statsdClient statsd.ClientInterface
	scannerChan  chan string
	sbomScanner  *sbomscanner.Scanner

	sbomGenerations       *atomic.Uint64
	failedSBOMGenerations *atomic.Uint64
	sbomsCacheHit         *atomic.Uint64
	sbomsCacheMiss        *atomic.Uint64

	// context tags and attributes
	hostname    string
	source      string
	contextTags []string
}

// NewSBOMResolver returns a new instance of Resolver
func NewSBOMResolver(c *config.RuntimeSecurityConfig, statsdClient statsd.ClientInterface) (*Resolver, error) {
	sbomScanner, err := sbomscanner.CreateGlobalScanner(coreconfig.SystemProbe)
	if err != nil {
		return nil, err
	}
	if sbomScanner == nil {
		return nil, errors.New("sbom is disabled")
	}

	sbomsCache, err := simplelru.NewLRU[string, sbomPackageFiles](c.SBOMResolverWorkloadsCacheSize, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't create new SBOMResolver: %w", err)
	}

	resolver := &Resolver{
		statsdClient: statsdClient,
		workloads:    make(map[string]*workloadEntry),
		sbomsCache:   sbomsCache,

		scannerChan: make(chan string, 100),
		sbomScanner: sbomScanner,

		sbomGenerations:       atomic.NewUint64(0),
		failedSBOMGenerations: atomic.NewUint64(0),
		sbomsCacheHit:         atomic.NewUint64(0),
		sbomsCacheMiss:        atomic.NewUint64(0),
	}

	if !c.SBOMResolverEnabled {
		return resolver, nil
	}

	resolver.prepareContextTags()
	return resolver, nil
}

func (r *Resolver) prepareContextTags() {
	// add hostname tag
	hostname, err := utils.GetHostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	r.hostname = hostname
	r.contextTags = append(r.contextTags, fmt.Sprintf("host:%s", r.hostname))

	// merge tags from config
	for _, tag := range configUtils.GetConfiguredTags(coreconfig.Datadog, true) {
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
func (r *Resolver) Start(ctx context.Context) {
	r.sbomScanner.Start(ctx)

	go func() {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return
			case containerID := <-r.scannerChan:
				if err := retry.Do(func() error {
					return r.analyzeWorkload(containerID)
				}, retry.Attempts(maxSBOMGenerationRetries), retry.Delay(20*time.Millisecond)); err != nil {
					seclog.Errorf(err.Error())
				}
			}
		}
	}()
}

// generateSBOM calls Trivy to generate the SBOM of a sbom
func (r *Resolver) generateSBOM(root string) (*trivy.TrivyReport, error) {
	seclog.Infof("Generating SBOM for %s", root)
	r.sbomGenerations.Inc()

	scanRequest := &host.ScanRequest{Path: root}
	ch := make(chan sbompkg.ScanResult, 1)
	if err := r.sbomScanner.Scan(scanRequest, sbompkg.ScanOptions{Analyzers: []string{trivy.OSAnalyzers}, Fast: true}, ch); err != nil {
		r.failedSBOMGenerations.Inc()
		return nil, fmt.Errorf("failed to trigger SBOM generation for %s: %w", root, err)
	}

	result := <-ch

	if result.Error != nil {
		// TODO: add a retry mechanism for retryable errors
		return nil, fmt.Errorf("failed to generate SBOM for %s: %w", root, result.Error)
	}

	seclog.Infof("SBOM successfully generated from %s", root)

	trivyReport, ok := result.Report.(*trivy.TrivyReport)
	if !ok {
		return nil, fmt.Errorf("failed to convert report for %s", root)
	}
	return trivyReport, nil
}

func (r *Resolver) analyzeWorkload(containerID string) error {
	wl := r.GetWorkload(containerID)
	if wl == nil {
		return nil
	}

	// bail out if the workload has been analyzed while queued up
	r.sbomsCacheLock.RLock()
	if r.sbomsCache.Contains(wl.key) {
		r.sbomsCacheLock.RUnlock()
		return nil
	}
	r.sbomsCacheLock.RUnlock()

	var lastErr error
	var report *trivy.TrivyReport
	for _, rootCandidatePID := range wl.cgroup.GetPIDs() {
		// check if this pid still exists and is in the expected wl ID (if we loose an exit and need to wait for
		// the flush to remove a pid, there might be a significant delay before a PID is removed from this list. Checking
		// the wl ID reduces drastically the likelihood of this race)
		computedID, err := utils.GetProcContainerID(rootCandidatePID, rootCandidatePID)
		if err != nil {
			wl.cgroup.RemovePID(rootCandidatePID)
			continue
		}
		if string(computedID) != wl.containerID {
			wl.cgroup.RemovePID(rootCandidatePID)
			continue
		}

		report, lastErr = r.generateSBOM(utils.ProcRootPath(rootCandidatePID))
		if lastErr == nil {
			break
		} else {
			seclog.Errorf("couldn't generate SBOM: %v", lastErr)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	if report == nil {
		return fmt.Errorf("couldn't generate sbom: all root candidates failed")
	}

	files := make(sbomPackageFiles)
	for _, result := range report.Results {
		for _, resultPkg := range result.Packages {
			pkg := &Package{
				Name:       resultPkg.Name,
				Version:    resultPkg.Version,
				SrcVersion: resultPkg.SrcVersion,
			}
			for _, file := range resultPkg.SystemInstalledFiles {
				seclog.Tracef("indexing %s as %+v", file, pkg)
				files[file] = pkg
			}
		}
	}

	seclog.Infof("new sbom generated for '%s': %d files added", wl.containerID, len(files))

	r.sbomsCacheLock.Lock()
	r.sbomsCache.Add(wl.key, files)
	r.sbomsCacheLock.Unlock()
	return nil
}

// ResolvePackage returns the Package that owns the provided file. Make sure the internal fields of "file" are properly
// resolved.
func (r *Resolver) ResolvePackage(containerID string, file *model.FileEvent) *Package {
	wl := r.GetWorkload(containerID)
	if wl == nil {
		return nil
	}
	files, ok := r.sbomsCache.Get(wl.key)
	if !ok {
		return nil
	}
	pkg := files[file.PathnameStr]
	if pkg == nil && strings.HasPrefix(file.PathnameStr, "/usr") {
		pkg = files[file.PathnameStr[4:]]
	}
	return pkg
}

// OnWorkloadSelectorResolvedEvent is used to handle the creation of a new cgroup with its resolved tags
func (r *Resolver) OnWorkloadSelectorResolvedEvent(cgroup *cgroupModel.CacheEntry) {
	r.Retain(cgroup.ID, cgroup)
}

// Retain increments the reference counter of the SBOM of a sbom
func (r *Resolver) Retain(containerID string, cgroup *cgroupModel.CacheEntry) {
	// We don't scan hosts for now
	if len(containerID) == 0 {
		return
	}

	wl := r.GetWorkload(containerID)
	if wl == nil {
		wl = newWorkloadEntry(containerID, cgroup)
		r.workloadsLock.Lock()
		r.workloads[containerID] = wl
		r.workloadsLock.Unlock()
	}

	// check if this workload has been scanned before
	r.sbomsCacheLock.RLock()
	loaded := r.sbomsCache.Contains(wl.key)
	r.sbomsCacheLock.RUnlock()
	if loaded {
		r.sbomsCacheHit.Inc()
	} else {
		r.sbomsCacheMiss.Inc()
		select {
		case r.scannerChan <- wl.containerID:
		default:
		}
	}
}

// GetWorkload returns the sbom of a provided ID
func (r *Resolver) GetWorkload(id string) *workloadEntry {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()
	return r.workloads[id]
}

// OnCGroupDeletedEvent is used to handle a CGroupDeleted event
func (r *Resolver) OnCGroupDeletedEvent(sbom *cgroupModel.CacheEntry) {
	r.Delete(sbom.ID)
}

// Delete removes the SBOM of the provided cgroup
func (r *Resolver) Delete(id string) {
	wl := r.GetWorkload(id)
	if wl == nil {
		return
	}

	seclog.Infof("deleting SBOM entry for '%s'", wl.containerID)
	r.workloadsLock.Lock()
	delete(r.workloads, wl.containerID)
	r.workloadsLock.Unlock()
}

func (r *Resolver) SendStats() error {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()
	if val := float64(len(r.workloads)); val > 0 {
		if err := r.statsdClient.Gauge(metrics.MetricSBOMResolverActiveSBOMs, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverActiveSBOMs: %w", err)
		}
	}

	if val := r.sbomGenerations.Swap(0); val > 0 {
		if err := r.statsdClient.Count(metrics.MetricSBOMResolverSBOMGenerations, int64(val), []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverSBOMGenerations: %w", err)
		}
	}

	r.sbomsCacheLock.RLock()
	defer r.sbomsCacheLock.RUnlock()
	if val := float64(r.sbomsCache.Len()); val > 0 {
		if err := r.statsdClient.Gauge(metrics.MetricSBOMResolverSBOMCacheLen, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverSBOMCacheLen: %w", err)
		}
	}

	if val := int64(r.sbomsCacheHit.Swap(0)); val > 0 {
		if err := r.statsdClient.Count(metrics.MetricSBOMResolverSBOMCacheHit, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverSBOMCacheHit: %w", err)
		}
	}

	if val := int64(r.sbomsCacheMiss.Swap(0)); val > 0 {
		if err := r.statsdClient.Count(metrics.MetricSBOMResolverSBOMCacheMiss, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverSBOMCacheMiss: %w", err)
		}
	}

	if val := int64(r.failedSBOMGenerations.Swap(0)); val > 0 {
		if err := r.statsdClient.Count(metrics.MetricSBOMResolverFailedSBOMGenerations, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSBOMResolverFailedSBOMGenerations: %w", err)
		}
	}

	return nil
}
