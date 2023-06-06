// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package usm

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)



// Disclaimer: this (hacky) code is just part of of a quick PoC and won't be merged
func TraceIstio(config *config.Config, m *errtelemetry.Manager) {
	envoyBinary := []byte("/usr/local/bin/envoy")
	procRoot := util.HostProc()
	hookFn := addHooks(m, openSSLProbes)

	util.WithAllProcs(procRoot, func(pid int) error {
		cmdPath := fmt.Sprintf("%s/%d/cmdline", procRoot, pid)
		cmd, err := ioutil.ReadFile(cmdPath)
		if err != nil {
			return nil
		}

		if !bytes.HasPrefix(cmd, envoyBinary) {
			return nil
		}

		pidRoot := fmt.Sprintf("%s/%d/root", procRoot, pid)
		envoyPath := fmt.Sprintf("%s/%s", pidRoot, string(envoyBinary))
		pi, err := newPathIdentifier(envoyPath)
		if err != nil {
			log.Errorf("couldn't create identifier path", err)
			return nil
		}

		err = hookFn(pi, pidRoot, string(envoyBinary))
		if err != nil {
			log.Errorf("error tracing envoy: %s", err)
		}

		log.Infof("tracing envoy on pid=%s", pidRoot)

		return nil
	})
}
