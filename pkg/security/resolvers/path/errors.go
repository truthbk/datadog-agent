// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package path

import (
	"errors"
	"fmt"
)

// ErrResolutionNotCritical defines a non critical error
type ErrPathResolutionNotCritical struct {
	Err error
}

// Error implements the error interface
func (e *ErrPathResolutionNotCritical) Error() string {
	return fmt.Errorf("non critical path resolution error: %w", e.Err).Error()
}

// Unwrap implements the error interface
func (e *ErrPathResolutionNotCritical) Unwrap() error {
	return e.Err
}

// ErrPathResolution defines a non critical error
type ErrPathResolution struct {
	Err error
}

// Error implements the error interface
func (e *ErrPathResolution) Error() string {
	return fmt.Errorf("path resolution error: %w", e.Err).Error()
}

// Unwrap implements the error interface
func (e *ErrPathResolution) Unwrap() error {
	return e.Err
}

// ErrTruncatedPath is used to notify that a path was truncated
type ErrTruncatedPath struct{}

func (err ErrTruncatedPath) Error() string {
	return "truncated_path"
}

var errTruncatedPath ErrTruncatedPath

type pathRingsResolutionFailureCause uint32

const (
	drUnknown pathRingsResolutionFailureCause = iota
	drInvalidInode
	drDentryDiscarded
	drDentryResolution
	drDentryBadName
	drDentryMaxTailCall
	pathRefLengthTooBig
	pathRefLengthZero
	pathRefLengthTooSmall
	pathRefReadCursorOOB
	pathRefInvalidCPU
	pathRingsReadOverflow
	invalidFrontWatermarkSize
	invalidBackWatermarkSize
	frontWatermarkValueMismatch
	backWatermarkValueMismatch
	maxPathResolutionFailureCause // must be the last one
)

var pathRingsResolutionFailureCauses = [maxPathResolutionFailureCause]string{
	"unknown",
	"invalid_inode",
	"discarded_dentry",
	"dentry_resolution_error",
	"dentry_bad_name",
	"dentry_tailcall_limit",
	"too_big",
	"zero_length",
	"too_small",
	"out_of_bounds",
	"invalid_cpu",
	"read_overflow",
	"invalid_front_watermark_size",
	"invalid_back_watermark_size",
	"front_watermark_mismatch",
	"back_watermark_mismatch",
}

func (cause pathRingsResolutionFailureCause) String() string {
	return pathRingsResolutionFailureCauses[cause]
}

var (
	ErrDrUnknown                   = errors.New("unknown dentry resolution error")
	ErrDrInvalidInode              = errors.New("dentry with invalid inode")
	ErrDrDentryDiscarded           = errors.New("dentry discarded")
	ErrDrDentryResolution          = errors.New("dentry resolution error")
	ErrDrDentryBadName             = errors.New("dentry bad name")
	ErrDrDentryMaxTailCall         = errors.New("dentry tailcall limit reached")
	ErrPathRefLengthTooBig         = errors.New("path ref length exceeds ring buffer size")
	ErrPathRefLengthZero           = errors.New("path ref length is zero")
	ErrPathRefLengthTooSmall       = errors.New("path ref length is too small")
	ErrPathRefReadCursorOOB        = errors.New("path ref read cursor is out-of-bounds")
	ErrPathRefInvalidCPU           = errors.New("path ref cpu is invalid")
	ErrPathRingsReadOverflow       = errors.New("read from path rings map overflow")
	ErrInvalidFrontWatermarkSize   = errors.New("front watermark read from path rings map has invalid size")
	ErrInvalidBackWatermarkSize    = errors.New("back watermark read from path rings map has invalid size")
	ErrFrontWatermarkValueMismatch = errors.New("mismatch between path ref watermark and front watermark from path rings")
	ErrBackWatermarkValueMismatch  = errors.New("mismatch between path ref watermark and back watermark from path rings")
)
