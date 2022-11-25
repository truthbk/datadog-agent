// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"github.com/cilium/ebpf/perf"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

// ExtractEventInfo extracts cpu and timestamp from the raw data event
func ExtractEventInfo(record *perf.Record) (QuickInfo, error) {
	if len(record.RawSample) < 16 {
		return QuickInfo{}, model.ErrNotEnoughData
	}

	return QuickInfo{
		cpu:       model.ByteOrder.Uint64(record.RawSample[0:8]),
		timestamp: model.ByteOrder.Uint64(record.RawSample[8:16]),
	}, nil
}
