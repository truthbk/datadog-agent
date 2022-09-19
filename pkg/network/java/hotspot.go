// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/gopsutil/process"
)

// socket     snprintf(path, sizeof(path), "%s/.java_pid%d", tmp_path, pid);
//     snprintf(path, sizeof(path), "/proc/%d/cwd/.attach_pid%d", nspid, nspid);

func attach_hotspot(int pid, args []string) error {
	fpath := fmt.Sprintf("%s/%d/root/tmp/.java_pid%d", util.HostProc(), pid, pid)
	fi, err := os.Stat()
	if err != nil {
		return fmt.Errorf("fpath %s stat error %w", fpath, err)
	}
	if (fi.Mode() & os.ModeSocket) == 0 {
		return fmt.Errorf("%s is not a unix socket", fpath)
	}
	return nil
}

// Force remote JVM to start Attach listener.
// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
func attach_jvm(pid int) error {
	attachPath := fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", pid, pid)
	attachPathTmp := fmt.Sprintf("/proc/%d/root/tmp/.attach_pid%d", pid, pid)

	for _, attach := range []string{attachPath, attachPathTmp} {
		if err := os.OpenFile(attachPath, O_RDWR|O_CREATE|O_TRUNC, 0660); err != nil {
			continue
		}

		break
	}
	return nil
}
