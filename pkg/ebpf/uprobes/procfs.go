// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package uprobes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// ProcInfo holds the information extracted from procfs, to avoid repeat calls to the filesystem.
type ProcInfo struct {
	procRoot string
	PID      uint32
	exe      string
	comm     string
}

// NewProcInfo creates a new ProcInfo object.
func NewProcInfo(procRoot string, pid uint32) *ProcInfo {
	return &ProcInfo{
		procRoot: procRoot,
		PID:      pid,
	}
}

func procPath(p *ProcInfo, procFile string) string {
	pidAsStr := strconv.FormatUint(uint64(p.PID), 10)
	return filepath.Join(p.procRoot, pidAsStr, procFile)
}

// Exe returns the path to the executable of the process.
func (p *ProcInfo) Exe() (string, error) {
	var err error
	if p.exe == "" {
		p.exe, err = os.Readlink(procPath(p, "exe"))
		if err != nil {
			return "", err
		}
	}

	if p.exe == "" {
		return "", errors.New("exe link is empty")
	}

	return p.exe, nil
}

const (
	// Defined in https://man7.org/linux/man-pages/man5/proc.5.html.
	taskCommLen = 16
)

var (
	taskCommLenBufferPool = sync.Pool{
		New: func() any {
			buf := make([]byte, taskCommLen)
			return &buf
		},
	}
)

func (p *ProcInfo) readComm(commFile string) (string, error) {
	file, err := os.Open(commFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := taskCommLenBufferPool.Get().(*[]byte)
	defer taskCommLenBufferPool.Put(buf)
	n, err := file.Read(*buf)
	if err != nil {
		// short living process can hit here, or slow start of another process.
		return "", nil
	}
	return string(bytes.TrimSpace((*buf)[:n])), nil
}

// Comm returns the command name of the process.
func (p *ProcInfo) Comm() (string, error) {
	var err error
	if p.comm == "" {
		p.comm, err = p.readComm(procPath(p, "comm"))
		if err != nil {
			return "", err
		}
	}

	return p.comm, nil
}
