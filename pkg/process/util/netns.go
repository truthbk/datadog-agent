// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package util

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"syscall"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type NameSpaceType = int

const (
	IPC  = NameSpaceType(syscall.CLONE_NEWIPC)
	NET  = NameSpaceType(syscall.CLONE_NEWNET)
	MNT  = NameSpaceType(syscall.CLONE_NEWNS)
	PID  = NameSpaceType(syscall.CLONE_NEWPID)
	USER = NameSpaceType(syscall.CLONE_NEWUSER)
	UTS  = NameSpaceType(syscall.CLONE_NEWUTS)
)

var mapNSClonePath = map[NameSpaceType]string{
	IPC:  "/ns/ipc",
	NET:  "/ns/net",
	MNT:  "/ns/mnt",
	PID:  "/ns/pid",
	USER: "/ns/user",
	UTS:  "/ns/uts",
}

type ProcessNameSpaces struct {
	procRoot string
	pid      int
	m        map[NameSpaceType]netns.NsHandle
}

func NewProcessNameSpaces(procRoot string, pid int, nss ...NameSpaceType) (pns *ProcessNameSpaces, err error) {
	pns = &ProcessNameSpaces{
		procRoot: procRoot,
		pid:      pid,
		m:        make(map[NameSpaceType]netns.NsHandle),
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, ns := range nss {
		pns.m[ns], err = netns.GetFromPath(path.Join(procRoot, strconv.Itoa(pid), mapNSClonePath[ns]))
		if err != nil {
			return pns, err
		}
	}
	return pns, nil
}

func (pns *ProcessNameSpaces) Close() {
	for _, ns := range pns.m {
		_ = ns.Close()
	}
}

// WithNS executes the given function in the given namespaces set by NewProcessNameSpaces()
// and then switches back to the previous namespace.
func (pns *ProcessNameSpaces) WithNS(prevNS *ProcessNameSpaces, fn func() error) error {
	for NStype, ns := range pns.m {
		if _, found := prevNS.m[NStype]; !found {
			return fmt.Errorf("namespace %+v is not set in the caller (previous) namespace", ns)
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var err error
	err = nil
	var ns netns.NsHandle
	for _, NStype := range []int{NET, IPC, MNT} {
		ns = pns.m[NStype]
		if ns.Equal(prevNS.m[NStype]) {
			continue
		}

		fmt.Println(ns)
		if err = netns.Setns(ns, 0); err != nil {
			fmt.Println("notnil", ns, NStype, err)
			break
		}
		ns.Close()
	}
	if err != nil {
		return fmt.Errorf("set namespace %+v failed %w", ns, err)
	}

	fnErr := fn()

	var nsErr error
	for NStype, ns := range prevNS.m {
		if err := netns.Setns(ns, NStype); err != nil {
			nsErr = err
		}
	}

	if fnErr != nil {
		return fnErr
	}
	return nsErr
}

// WithRootNS executes a function within root network namespace and then switch back
// to the previous namespace. If the thread is already in the root network namespace,
// the function is executed without calling SYS_SETNS.
func WithRootNS(procRoot string, fn func() error) error {
	rootNS, err := GetRootNetNamespace(procRoot)
	if err != nil {
		return err
	}

	return WithNS(procRoot, rootNS, fn)
}

// WithNS executes the given function in the given network namespace, and then
// switches back to the previous namespace.
func WithNS(procRoot string, ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevNS, err := netns.Get()
	if err != nil {
		return err
	}

	if ns.Equal(prevNS) {
		return fn()
	}

	if err := netns.Set(ns); err != nil {
		return err
	}

	fnErr := fn()
	nsErr := netns.Set(prevNS)
	if fnErr != nil {
		return fnErr
	}
	return nsErr
}

func WithNetNS(procRoot string, ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prevNS, err := netns.Get()
	if err != nil {
		return err
	}

	if ns.Equal(prevNS) {
		return fn()
	}

	if err := netns.Set(ns); err != nil {
		return err
	}

	fnErr := fn()
	nsErr := netns.Set(prevNS)
	if fnErr != nil {
		return fnErr
	}
	return nsErr
}

// GetNetNamespaces returns a list of network namespaces on the machine. The caller
// is responsible for calling Close() on each of the returned NsHandle's.
func GetNetNamespaces(procRoot string) ([]netns.NsHandle, error) {
	var nss []netns.NsHandle
	seen := make(map[string]interface{})
	err := WithAllProcs(procRoot, func(pid int) error {
		ns, err := netns.GetFromPath(path.Join(procRoot, fmt.Sprintf("%d/ns/net", pid)))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
				log.Errorf("error while reading %s: %s", path.Join(procRoot, fmt.Sprintf("%d/ns/net", pid)), err)
			}
			return nil
		}

		uid := ns.UniqueId()
		if _, ok := seen[uid]; ok {
			ns.Close()
			return nil
		}

		seen[uid] = struct{}{}
		nss = append(nss, ns)
		return nil
	})

	if err != nil {
		// close all the accumulated ns handles
		for _, ns := range nss {
			ns.Close()
		}

		return nil, err
	}

	return nss, nil
}

// GetCurrentIno returns the ino number for the current network namespace
func GetCurrentIno() (uint32, error) {
	curNS, err := netns.Get()
	if err != nil {
		return 0, err
	}
	defer curNS.Close()

	return GetInoForNs(curNS)
}

// GetRootNetNamespace gets the root network namespace
func GetRootNetNamespace(procRoot string) (netns.NsHandle, error) {
	return GetNetNamespaceFromPid(procRoot, 1)
}

// GetNetNamespaceFromPid gets the network namespace for a given `pid`
func GetNetNamespaceFromPid(procRoot string, pid int) (netns.NsHandle, error) {
	return netns.GetFromPath(path.Join(procRoot, fmt.Sprintf("%d/ns/net", pid)))
}

// GetNetNsInoFromPid gets the network namespace inode number for the given
// `pid`
func GetNetNsInoFromPid(procRoot string, pid int) (uint32, error) {
	ns, err := GetNetNamespaceFromPid(procRoot, pid)
	if err != nil {
		return 0, err
	}

	defer ns.Close()

	return GetInoForNs(ns)
}

// GetInoForNs gets the inode number for the given network namespace
func GetInoForNs(ns netns.NsHandle) (uint32, error) {
	if ns.Equal(netns.None()) {
		return 0, fmt.Errorf("net ns is none")
	}

	var s syscall.Stat_t
	if err := syscall.Fstat(int(ns), &s); err != nil {
		return 0, err
	}

	return uint32(s.Ino), nil
}
