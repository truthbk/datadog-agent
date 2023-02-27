// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sources

import (
	"fmt"
	"sync"
)

type FileStatus struct {
	sync.RWMutex
	totalCount    int
	activeTailers int
}

func NewFileStatus() *FileStatus {
	return &FileStatus{}
}

func (t *FileStatus) InfoKey() string {
	return "File Status"
}

func (t *FileStatus) Info() []string {
	t.RLock()
	defer t.RUnlock()
	return []string{fmt.Sprintf("%d files tailed out of %d files matching", t.activeTailers, t.totalCount)}
}

func (t *FileStatus) SetTotal(total int) {
	t.Lock()
	defer t.Unlock()
	t.totalCount = total
}

func (t *FileStatus) AddTailer() {
	t.Lock()
	defer t.Unlock()
	t.activeTailers++
}

func (t *FileStatus) RemoveTailer() {
	t.Lock()
	defer t.Unlock()
	t.activeTailers--
}
