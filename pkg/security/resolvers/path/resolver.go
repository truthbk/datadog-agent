// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package path

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path"
	"strings"
	"syscall"
	"unsafe"

	"github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	"github.com/DataDog/datadog-agent/pkg/security/probe/erpc"
	"github.com/DataDog/datadog-agent/pkg/security/probe/managerhelper"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/dentry"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/mount"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	manager "github.com/DataDog/ebpf-manager"
	"golang.org/x/sys/unix"
)

type ResolverInterface interface {
	ResolveBasename(e *model.FileFields) string
	ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error)
	SetMountRoot(ev *model.Event, e *model.Mount) error
	ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error)
	SetMountPoint(ev *model.Event, e *model.Mount) error
	ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error)
	SendStats() error
	Start(*manager.Manager) error
	Close() error
}

// NoResolver returns an empty resolver
type NoResolver struct {
}

// ResolveBasename resolves an inode/mount ID pair to a file basename
func (n *NoResolver) ResolveBasename(e *model.FileFields) string {
	return ""
}

// ResolveFileFieldsPath resolves an inode/mount ID pair to a full path
func (n *NoResolver) ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error) {
	return "", nil
}

// SetMountRoot set the mount point information
func (n *NoResolver) SetMountRoot(ev *model.Event, e *model.Mount) error {
	return nil
}

// ResolveMountRoot resolves the mountpoint to a full path
func (n *NoResolver) ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error) {
	return "", nil
}

// SetMountPoint set the mount point information
func (n *NoResolver) SetMountPoint(ev *model.Event, e *model.Mount) error {
	return nil
}

// ResolveMountPoint resolves the mountpoint to a full path
func (n *NoResolver) ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error) {
	return "", nil
}

func (n *NoResolver) SendStats() error {
	return nil
}

func (n *NoResolver) Start(m *manager.Manager) error {
	return nil
}

func (n *NoResolver) Close() error {
	return nil
}

// Resolver describes a resolvers for path and file names
type Resolver struct {
	dentryResolver *dentry.Resolver
	mountResolver  *mount.Resolver
}

// NewResolver returns a new path resolver
func NewResolver(dentryResolver *dentry.Resolver, mountResolver *mount.Resolver) *Resolver {
	return &Resolver{dentryResolver: dentryResolver, mountResolver: mountResolver}
}

type pathResolutionFailureCause uint8

const (
	unknown pathResolutionFailureCause = iota
	truncated
	invalidLength
	tooBig
	outOfBounds
	invalidCPU
	hashMismatch
	maxFailureCause
)

var pathResolutionFailureCauses = [...]string{
	"unknown",
	"truncated",
	"invalid_length",
	"too_big",
	"out_of_bounds",
	"invalid_cpu",
	"hash_mismatch",
}

func (cause pathResolutionFailureCause) String() string {
	return pathResolutionFailureCauses[cause]
}

const (
	PathRingBuffersSize = uint32(131072)
	WatermarkSize       = uint32(8)
)

// ResolverOpts defines mount resolver options
type ResolverOpts struct {
	UseCache       bool
	UseRingBuffers bool
	UseERPC        bool
}

// Resolver describes a resolvers for path and file names
type PathRingsResolver struct {
	opts            ResolverOpts
	mountResolver   *mount.Resolver
	statsdClient    statsd.ClientInterface
	failureCounters [maxFailureCause]*atomic.Int64
	successCounter  *atomic.Int64
	// RingBuffers
	pathRings       []byte
	numCPU          uint32
	watermarkBuffer *bytes.Buffer
	// eRPC
	erpc          *erpc.ERPC
	erpcBuffer    []byte
	erpcChallenge uint32
	erpcRequest   erpc.ERPCRequest
}

// NewResolver returns a new path resolver
func NewPathRingsResolver(opts ResolverOpts, mountResolver *mount.Resolver, eRPC *erpc.ERPC, statsdClient statsd.ClientInterface) *PathRingsResolver {
	pr := &PathRingsResolver{
		opts:            opts,
		mountResolver:   mountResolver,
		statsdClient:    statsdClient,
		successCounter:  atomic.NewInt64(0),
		watermarkBuffer: bytes.NewBuffer(make([]byte, 0, WatermarkSize)),
		erpc:            eRPC,
	}

	for i := 0; i < int(maxFailureCause); i++ {
		pr.failureCounters[i] = atomic.NewInt64(0)
	}

	return pr
}

func reversePathParts(pathStr string) string {
	if pathStr == "/" {
		return pathStr
	}

	pathStr = strings.TrimSuffix(pathStr, "/")
	parts := strings.Split(pathStr, "/")

	if len(parts) == 0 {
		return "/"
	}

	var builder strings.Builder

	// pre-allocation
	for _, part := range parts {
		builder.Grow(len(part) + 1)
	}

	// reverse iteration
	for i := 0; i < len(parts); i++ {
		j := len(parts) - 1 - i
		builder.WriteRune('/')
		builder.WriteString(parts[j])
	}

	return builder.String()
}

func (pr *PathRingsResolver) resolvePathFromRingBuffers(ref *model.PathRingBufferRef) (string, error) {
	if ref.Length == math.MaxUint32 {
		pr.failureCounters[truncated].Inc()
		return "", errTruncatedPath
	}

	if ref.Length == 0 || ref.Length <= 2*WatermarkSize {
		pr.failureCounters[invalidLength].Inc()
		return "", fmt.Errorf("invalid path ref length: %d", ref.Length)
	}

	if ref.Length > PathRingBuffersSize {
		pr.failureCounters[tooBig].Inc()
		return "", fmt.Errorf("path ref length exceeds ring buffer size: %d", ref.Length)
	}

	if ref.ReadCursor > PathRingBuffersSize {
		pr.failureCounters[outOfBounds].Inc()
		return "", fmt.Errorf("path ref read cursor is out-of-bounds: %d", ref.ReadCursor)
	}

	if ref.CPU >= uint32(pr.numCPU) {
		pr.failureCounters[invalidCPU].Inc()
		return "", fmt.Errorf("path ref CPU number is invalid: %d", ref.CPU)
	}

	cpuOffset := ref.CPU * PathRingBuffersSize
	readOffset := ref.ReadCursor

	pr.watermarkBuffer.Reset()
	if readOffset+WatermarkSize > PathRingBuffersSize {
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset+readOffset : cpuOffset+PathRingBuffersSize]); err != nil {
			return "", err
		}
		remaining := WatermarkSize - (PathRingBuffersSize - readOffset)
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset : cpuOffset+remaining]); err != nil {
			return "", err
		}
		readOffset = remaining
	} else {
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset+readOffset : cpuOffset+readOffset+WatermarkSize]); err != nil {
			return "", err
		}
		readOffset += WatermarkSize
	}

	if pr.watermarkBuffer.Len() != int(WatermarkSize) {
		return "", fmt.Errorf("front watermark has invalid size: %d", pr.watermarkBuffer.Len())
	}

	frontWatermark := model.ByteOrder.Uint64(pr.watermarkBuffer.Bytes())
	if frontWatermark != ref.Watermark {
		return "", fmt.Errorf("front waterwark has invalid value")
	}

	var pathStr string
	segmentLen := ref.Length - (2 * WatermarkSize)

	if readOffset+segmentLen > PathRingBuffersSize {
		firstPart := model.NullTerminatedString(pr.pathRings[cpuOffset+readOffset : cpuOffset+PathRingBuffersSize])
		remaining := segmentLen - (PathRingBuffersSize - readOffset)
		secondPart := model.NullTerminatedString(pr.pathRings[cpuOffset : cpuOffset+remaining])
		pathStr = firstPart + secondPart
		readOffset = remaining
	} else {
		pathStr = model.NullTerminatedString(pr.pathRings[cpuOffset+readOffset : cpuOffset+readOffset+segmentLen])
		readOffset += segmentLen
	}

	pr.watermarkBuffer.Reset()
	if readOffset+WatermarkSize > PathRingBuffersSize {
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset+readOffset : cpuOffset+PathRingBuffersSize]); err != nil {
			return "", err
		}
		remaining := WatermarkSize - (PathRingBuffersSize - readOffset)
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset : cpuOffset+remaining]); err != nil {
			return "", err
		}
		readOffset = remaining
	} else {
		if _, err := pr.watermarkBuffer.Write(pr.pathRings[cpuOffset+readOffset : cpuOffset+readOffset+WatermarkSize]); err != nil {
			return "", err
		}
		readOffset += WatermarkSize
	}

	if pr.watermarkBuffer.Len() != int(WatermarkSize) {
		return "", fmt.Errorf("back watermark has invalid size: %d", pr.watermarkBuffer.Len())
	}

	backWatermark := model.ByteOrder.Uint64(pr.watermarkBuffer.Bytes())
	if backWatermark != ref.Watermark {
		return "", fmt.Errorf("back waterwark has invalid value")
	}

	pr.successCounter.Inc()

	return reversePathParts(pathStr), nil
}

// preventSegmentMajorPageFault prepares the userspace memory area where the dentry resolver response is written. Used in kernel versions where BPF_F_MMAPABLE array maps are not yet available.
func (pr *PathRingsResolver) preventBufferMajorPageFault() {
	// if we don't access the buffer, the eBPF program can't write to it ... (major page fault)
	for i := 0; i < len(pr.erpcBuffer); i += os.Getpagesize() {
		pr.erpcBuffer[i] = 0
	}
}

// ResolvePathFromERPC resolves the path of the provided path_ref
func (pr *PathRingsResolver) resolvePathFromERPC(ref *model.PathRingBufferRef) (string, error) {
	if 4+2*WatermarkSize+ref.Length > uint32(len(pr.erpcBuffer)) {
		return "", fmt.Errorf("path ref is too big: %d bytes", ref.Length)
	}

	challenge := pr.erpcChallenge
	pr.erpcChallenge++

	// create eRPC request
	pr.erpcRequest.OP = erpc.ResolvePathSegmentOp
	// 0-8 and 8-12 already populated at start
	model.ByteOrder.PutUint32(pr.erpcRequest.Data[12:16], ref.CPU)
	model.ByteOrder.PutUint32(pr.erpcRequest.Data[16:20], ref.ReadCursor)
	model.ByteOrder.PutUint32(pr.erpcRequest.Data[20:24], ref.Length)
	model.ByteOrder.PutUint32(pr.erpcRequest.Data[24:28], challenge)

	pr.preventBufferMajorPageFault()

	err := pr.erpc.Request(&pr.erpcRequest)
	if err != nil {
		return "", fmt.Errorf("unable to get path from ref %+v with eRPC: %w", ref, err)
	}

	segmentLen := ref.Length - (2 * WatermarkSize)

	ackChallenge := model.ByteOrder.Uint32(pr.erpcBuffer[0:4])
	if challenge != ackChallenge {
		return "", fmt.Errorf("invalid challenge (expected %d, got %d, ref %+v)", challenge, ackChallenge, ref)
	}

	frontWatermark := model.ByteOrder.Uint64(pr.erpcBuffer[4:12])
	if frontWatermark != ref.Watermark {
		return "", fmt.Errorf("invalid front watermark (expected %d, got %d, challenge %d, ref %+v)", ref.Watermark, frontWatermark, challenge, ref)
	}

	backWatermark := model.ByteOrder.Uint64(pr.erpcBuffer[12+segmentLen : 12+segmentLen+8])
	if backWatermark != ref.Watermark {
		return "", fmt.Errorf("invalid back watermark (expected %d, got %d, challenge %d, ref %+v)", ref.Watermark, backWatermark, challenge, ref)
	}

	path := model.NullTerminatedString(pr.erpcBuffer[12 : 12+segmentLen])
	if len(path) == 0 || len(path) > 0 && path[0] == 0 {
		return "", fmt.Errorf("couldn't resolve path (len: %d)", len(path))
	}

	return reversePathParts(path), nil
}

func (pr *PathRingsResolver) resolvePath(ref *model.PathRingBufferRef) (string, error) {
	var path string
	var err error

	if pr.opts.UseRingBuffers {
		path, err = pr.resolvePathFromRingBuffers(ref)
		if err == nil {
			// put in cache here
			return path, nil
		}
	}

	// TODO: resolveFromCache

	if pr.opts.UseERPC {
		path, err = pr.resolvePathFromERPC(ref)
		if err == nil {
			// put in cache here
			return path, nil
		}
	}
	return path, err
}

func (pr *PathRingsResolver) ResolveBasename(e *model.FileFields) string {
	resolvedPath, err := pr.resolvePath(&e.PathRef)
	if err != nil {
		return ""
	}
	return path.Base(resolvedPath)
}

func (pr *PathRingsResolver) ResolveFileFieldsPath(e *model.FileFields, pidCtx *model.PIDContext, ctrCtx *model.ContainerContext) (string, error) {
	pathStr, err := pr.resolvePath(&e.PathRef)
	if err != nil {
		return pathStr, &ErrPathResolution{Err: err}
	}

	if e.IsFileless() {
		return pathStr, nil
	}

	mountPath, err := pr.mountResolver.ResolveMountPath(e.MountID, pidCtx.Pid, ctrCtx.ID)
	if err != nil {
		if _, err := pr.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
		}
		return pathStr, &ErrPathResolution{Err: err}
	}

	// This aims to handle bind mounts
	rootPath, err := pr.mountResolver.ResolveMountRoot(e.MountID, pidCtx.Pid, ctrCtx.ID)
	if err != nil {
		if _, err := pr.mountResolver.IsMountIDValid(e.MountID); errors.Is(err, mount.ErrMountKernelID) {
			return pathStr, &ErrPathResolutionNotCritical{Err: fmt.Errorf("mount ID(%d) invalid: %w", e.MountID, err)}
		}
		return pathStr, &ErrPathResolution{Err: err}
	}
	if strings.HasPrefix(pathStr, rootPath) && rootPath != "/" {
		pathStr = strings.Replace(pathStr, rootPath, "", 1)
	}

	if mountPath != "/" {
		pathStr = mountPath + pathStr
	}

	return pathStr, nil
}

// SetMountRoot set the mount point information
func (pr *PathRingsResolver) SetMountRoot(ev *model.Event, e *model.Mount) error {
	var err error
	e.RootStr, err = pr.resolvePath(&e.RootStrPathRef)
	if err != nil {
		return &ErrPathResolutionNotCritical{Err: err}
	}
	return nil
}

// ResolveMountRoot resolves the mountpoint to a full path
func (pr *PathRingsResolver) ResolveMountRoot(ev *model.Event, e *model.Mount) (string, error) {
	if len(e.RootStr) == 0 {
		if err := pr.SetMountRoot(ev, e); err != nil {
			return "", err
		}
	}
	return e.RootStr, nil
}

// SetMountPoint set the mount point information
func (pr *PathRingsResolver) SetMountPoint(ev *model.Event, e *model.Mount) error {
	var err error
	e.MountPointStr, err = pr.resolvePath(&e.MountPointPathRef)
	if err != nil {
		return &ErrPathResolutionNotCritical{Err: err}
	}
	return nil
}

// ResolveMountPoint resolves the mountpoint to a full path
func (r *PathRingsResolver) ResolveMountPoint(ev *model.Event, e *model.Mount) (string, error) {
	if len(e.MountPointStr) == 0 {
		if err := r.SetMountPoint(ev, e); err != nil {
			return "", err
		}
	}
	return e.MountPointStr, nil
}

func (pr *PathRingsResolver) Start(m *manager.Manager) error {
	if pr.pathRings != nil {
		return fmt.Errorf("path resolver already started")
	}

	numCPU, err := utils.NumCPU()
	if err != nil {
		return err
	}
	pr.numCPU = uint32(numCPU)

	if pr.opts.UseRingBuffers {
		pathRingsMap, err := managerhelper.Map(m, "pr_ringbufs")
		if err != nil {
			return err
		}

		pathRings, err := syscall.Mmap(pathRingsMap.FD(), 0, int(pr.numCPU*PathRingBuffersSize), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil || pathRings == nil {
			return fmt.Errorf("failed to mmap pr_ringbufs map: %w", err)
		}
		pr.pathRings = pathRings
	}

	if pr.opts.UseERPC {
		pr.erpcBuffer = make([]byte, 7*os.Getpagesize())
		pr.erpcChallenge = rand.Uint32()
		model.ByteOrder.PutUint64(pr.erpcRequest.Data[0:8], uint64(uintptr(unsafe.Pointer(&pr.erpcBuffer[0]))))
		model.ByteOrder.PutUint32(pr.erpcRequest.Data[8:12], uint32(len(pr.erpcBuffer)))
	}

	return nil
}

func (pr *PathRingsResolver) Close() error {
	if pr.opts.UseRingBuffers {
		return unix.Munmap(pr.pathRings)
	}
	return nil
}

func (pr *PathRingsResolver) SendStats() error {
	for cause, counter := range pr.failureCounters {
		val := counter.Swap(0)
		if val > 0 {
			tags := []string{fmt.Sprintf("cause:%s", pathResolutionFailureCause(cause).String())}
			_ = pr.statsdClient.Count(metrics.MetricPathResolutionFailure, val, tags, 1.0)
		}
	}

	val := pr.successCounter.Swap(0)
	if val > 0 {
		_ = pr.statsdClient.Count(metrics.MetricPathResolutionSuccess, val, []string{}, 1.0)
	}

	return nil
}
