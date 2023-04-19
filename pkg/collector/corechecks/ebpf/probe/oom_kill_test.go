// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package probe

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/process/statsd"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

const oomKilledPython = `
l = []
while True:
	l.append("." * (1024 * 1024))
`

func writeTempFile(t *testing.T, pattern string, content string) (*os.File, error) {
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return nil, err
	}

	return f, nil
}

func TestOOMKillCompile(t *testing.T) {
	kv, err := kernel.HostVersion()
	if err != nil {
		t.Fatal(err)
	}
	if kv < kernel.VersionCode(4, 9, 0) {
		t.Skipf("Kernel version %v is not supported by the OOM probe", kv)
	}

	cfg := testConfig()
	cfg.BPFDebug = true
	_, err = runtime.OomKill.Compile(cfg, []string{"-g"}, statsd.Client)
	require.NoError(t, err)
}

func TestOOMKillProbe(t *testing.T) {
	kv, err := kernel.HostVersion()
	if err != nil {
		t.Fatal(err)
	}
	if kv < kernel.VersionCode(4, 9, 0) {
		t.Skipf("Kernel version %v is not supported by the OOM probe", kv)
	}

	cfg := testConfig()
	oomKillProbe, err := NewOOMKillProbe(cfg)
	require.NoError(t, err)
	t.Cleanup(oomKillProbe.Close)

	pf, err := writeTempFile(t, "oom-kill-py", oomKilledPython)
	require.NoError(t, err)
	defer os.Remove(pf.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "systemd-run", "--scope", "-p", "MemoryLimit=1M", "python3", pf.Name())

	output, err := cmd.CombinedOutput()
	require.Error(t, err, "command should exit with error")
	exiterr, ok := err.(*exec.ExitError)
	require.True(t, ok, "err is not *exec.ExitError (type %T): %s (output: %s)", err, err, string(output))
	status, ok := exiterr.Sys().(syscall.WaitStatus)
	require.True(t, ok, "exiterr.Sys() should be syscall.WaitStatus (type %T): %s (output: %s)", err, err, string(output))
	if status.Signaled() {
		require.Equal(t, unix.SIGKILL, status.Signal(), "expected SIGKILL signal: %s (output: %s)", err, string(output))
	} else {
		require.Equal(t, 137, status.ExitStatus(), "expected exit code 137: %s (output: %s)", err, string(output))
	}

	var result OOMKillStats
	require.Eventually(t, func() bool {
		results := oomKillProbe.GetAndFlush()
		for _, r := range results {
			if r.TPid == uint32(cmd.Process.Pid) {
				result = r
				return true
			}
		}
		return false
	}, 1*time.Second, 200*time.Millisecond, "failed to find an OOM killed process with pid %d", cmd.Process.Pid)

	assert.Regexp(t, regexp.MustCompile("run-([0-9|a-z]*).scope"), result.CgroupName, "cgroup name")
	assert.Equal(t, result.TPid, result.Pid, "tpid == pid")
	assert.Equal(t, "python3", result.FComm, "fcomm")
	assert.Equal(t, "python3", result.TComm, "tcomm")
	assert.NotZero(t, result.Pages, "pages")
	assert.Equal(t, uint32(1), result.MemCgOOM, "memcg oom")
}

func testConfig() *ebpf.Config {
	cfg := ebpf.NewConfig()
	return cfg
}
