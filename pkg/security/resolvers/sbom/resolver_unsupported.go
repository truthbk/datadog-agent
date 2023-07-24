// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && !trivy

package sbom

import (
	"context"

	"github.com/DataDog/datadog-go/v5/statsd"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

type Resolver struct {
}

type SBOMListener interface {
}

type SBOM struct {
}

func (s *SBOM) WorkloadSelector() cgroupModel.WorkloadSelector {
	return cgroupModel.WorkloadSelector{}
}

func NewSBOMResolver(c *config.RuntimeSecurityConfig, statsdClient statsd.ClientInterface) (*Resolver, error) {
	return &Resolver{}, nil
}

func (r *Resolver) OnCGroupDeletedEvent(sbom *cgroupModel.CacheEntry) {
}

func (r *Resolver) OnWorkloadSelectorResolvedEvent(sbom *cgroupModel.CacheEntry) {
}

func (r *Resolver) ResolvePackage(containerID string, file *model.FileEvent) *Package {
	return nil
}

func (r *Resolver) SendStats() error {
	return nil
}

func (r *Resolver) RegisterListener(listener SBOMListener) {
}

func (r *Resolver) Start(ctx context.Context) {
}
