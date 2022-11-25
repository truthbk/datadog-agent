// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probectx

import (
	"time"

	pconfig "github.com/DataDog/datadog-agent/pkg/process/config"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf/kernel"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-go/v5/statsd"

	manager "github.com/DataDog/ebpf-manager"
)

type Resolver interface {
	ResolveFileFieldsPath(e *model.FileFields, ctx *model.PIDContext) (string, error)
	ResolveBasename(e *model.FileFields) string
}

type TimeResolver interface {
	ResolveMonotonicTimestamp(timestamp uint64) time.Time
	ComputeMonotonicTimestamp(timestamp time.Time) int64
}

type ProcessResolver interface {
	Walk(callback func(entry *model.ProcessCacheEntry))
	GetProcessArgv(pr *model.Process) ([]string, bool)
	GetProcessArgv0(pr *model.Process) (string, bool)
	GetProcessScrubbedArgv(pr *model.Process) ([]string, bool)
	GetProcessEnvs(pr *model.Process) ([]string, bool)
	GetProcessEnvp(pr *model.Process) ([]string, bool)
	NewProcessCacheEntry(pidContext model.PIDContext) *model.ProcessCacheEntry
	Resolve(pid, tid uint32) *model.ProcessCacheEntry
}

type TagsResolver interface {
	ResolveWithErr(id string) ([]string, error)
	Resolve(id string) []string
}

type DentryResolver interface {
	Resolve(mountID uint32, inode uint64, pathID uint32, cache bool) (string, error)
}

type UserGroupResolver interface {
	ResolveUser(uid int) (string, error)
	ResolveGroup(gid int) (string, error)
}

type MountResolver interface {
	GetFilesystem(mountID, pid uint32) (string, error)
}

type ProbeCtx struct {
	// Constants and configuration
	Manager      *manager.Manager
	Config       *config.Config
	StatsdClient statsd.ClientInterface
	// startTime     time.Time
	KernelVersion *kernel.Version

	// Events section
	ConstantOffsets   map[string]uint64
	Scrubber          *pconfig.DataScrubber
	TimeResolver      TimeResolver
	ProcessResolver   ProcessResolver
	TagsResolver      TagsResolver
	DentryResolver    DentryResolver
	UserGroupResolver UserGroupResolver
	MountResolver     MountResolver
	Resolver          Resolver
}
