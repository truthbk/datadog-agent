// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux

package flare

import (
	flaretypes "github.com/DataDog/datadog-agent/comp/core/flare/types"
)

func addSystemProbePlatformSpecificEntries(flaretypes.FlareBuilder) {}

func getLinuxKernelSymbols(flaretypes.FlareBuilder) error {
	return nil
}

func getLinuxKprobeEvents(flaretypes.FlareBuilder) error {
	return nil
}

func getLinuxDmesg(flaretypes.FlareBuilder) error {
	return nil
}

func getLinuxPid1MountInfo(flaretypes.FlareBuilder) error {
	return nil
}

func getLinuxTracingAvailableEvents(flaretypes.FlareBuilder) error {
	return nil
}

func getLinuxTracingAvailableFilterFunctions(flaretypes.FlareBuilder) error {
	return nil
}
