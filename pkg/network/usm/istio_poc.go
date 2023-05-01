// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package usm

import (
	"fmt"

	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/vishvananda/netns"
)

// Disclaimer: this (hacky) code is just part of of a quick PoC and won't be merged
func AttachFilterToAllNamespaces(filter *manager.Probe) []func() {
	var closeCBs []func()

	procRoot := util.HostProc()
	seen := make(map[string]struct{})
	err := util.WithAllProcs(util.HostProc(), func(pid int) error {
		path := fmt.Sprintf("%s/%d/ns/net", procRoot, pid)

		ns, err := netns.GetFromPath(path)
		if err != nil {
			return nil
		}

		defer ns.Close()
		uniqueID := ns.UniqueId()
		if _, ok := seen[uniqueID]; ok {
			return nil
		}

		seen[uniqueID] = struct{}{}
		callback, err := filterpkg.HeadlessSocketFilter(ns, filter)
		if err != nil {
			return nil
		}

		log.Debugf("attached socket-filter program to namespace=%s", path)
		closeCBs = append(closeCBs, callback)
		return nil
	})

	if err != nil {
		log.Debugf("error iterating over net namespaces: %s", err)
	}

	return closeCBs
}
