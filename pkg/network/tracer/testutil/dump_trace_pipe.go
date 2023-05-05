// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package testutil

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func DumpTrace(t *testing.T) {
	f, err := os.Open("/sys/kernel/debug/tracing/trace")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	b, err := io.ReadAll(f)
	require.NoError(t, err)
	t.Log(string(b))
}
