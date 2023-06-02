// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package usm

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/vishvananda/netns"
)

// Disclaimer: this (hacky) code is just part of of a quick PoC and won't be merged
func AttachFilterToAllNamespaces(config *config.Config, m *manager.Manager, filter *manager.Probe) []func() {
	var closeCBs []func()

	procRoot := util.HostProc()
	seen := make(map[string]struct{})

	// First attach to the root namespace
	rootNS, err := config.GetRootNetNs()
	if err != nil {
		return nil
	}

	cb, err := filterpkg.HeadlessSocketFilter(rootNS, filter)
	if err != nil {
		return nil
	}

	seen[rootNS.UniqueId()] = struct{}{}
	closeCBs = append(closeCBs, cb)

	err = util.WithAllProcs(util.HostProc(), func(pid int) error {
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
		identifier := manager.ProbeIdentificationPair{
			EBPFFuncName: filter.ProbeIdentificationPair.EBPFFuncName,
			UID:          uniqueID,
		}
		newProbe := &manager.Probe{
			ProbeIdentificationPair: identifier,
		}

		callback, err := filterpkg.HeadlessSocketFilter(ns, newProbe)
		if err != nil {
			return nil
		}

		log.Debugf("attached socket-filter program to namespace=%s", ns)
		closeCBs = append(closeCBs, func() {
			m.DetachHook(identifier)
			// add detach stuff here
			callback()
		})

		m.AddHook(filter.ProbeIdentificationPair.UID, newProbe)

		return nil
	})

	if err != nil {
		log.Debugf("error iterating over net namespaces: %s", err)
	}

	return closeCBs
}
