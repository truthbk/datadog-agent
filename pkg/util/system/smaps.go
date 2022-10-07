// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package system

type SelfMemStats map[string]SmapData

type SmapData struct {
	Rss          uint64
	Pss          uint64
	SharedClean  uint64
	SharedDirty  uint64
	PrivateClean uint64
	PrivateDirty uint64
	Referenced   uint64
	Anonymous    uint64
	Swap         uint64
	SwapPss      uint64
}
