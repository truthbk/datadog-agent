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
	"syscall"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	//	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/gopsutil/process"
)

func initialScanHostProc() error {
	fn := func(pid int) error {
		fmt.Printf("%v\n", pid)
		return nil
	}
	err := util.WithAllProcs(util.HostProc(), fn)
	if err != nil {
		return err
	}
	return nil
}

func Inject(pid int) error {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return err
	}
	uids, err := proc.Uids()
	if err != nil {
		return err
	}
	gids, err := proc.Gids()
	if err != nil {
		return err
	}
	fmt.Printf("%v %v %v\n", uids, gids, proc.NsPid)

	prevNS, err := util.NewProcessNameSpaces(util.HostProc(), os.Getpid(), util.NET, util.IPC, util.MNT)
	if err != nil {
		return fmt.Errorf("can't get previous namespace %w", err)
	}
	defer prevNS.Close()

	targetNS, err := util.NewProcessNameSpaces(util.HostProc(), pid, util.NET, util.IPC, util.MNT)
	if err != nil {
		return fmt.Errorf("can't get target namespace %w", err)
	}
	defer targetNS.Close()

	sendSIGQUIT := make(chan struct{}, 1)
	go func(sendSIGQUIT chan struct{}) {
		select {
		case <-sendSIGQUIT:
			fmt.Println("send sigquit")
			p, err := os.FindProcess(pid)
			if err != nil {
				fmt.Errorf("can't find process %d %w", pid, err)
			}
			err = p.Signal(syscall.SIGHUP)
			if err != nil {
				fmt.Errorf("can't send SIGQUIT to process %d %w", pid, err)
			}
		}
	}(sendSIGQUIT)

	fmt.Println("===")

	err = targetNS.WithNS(prevNS, func() error {
		fmt.Println("== exec in", os.Getpid())
		sendSIGQUIT <- struct{}{}
		return nil
	})
	fmt.Println(err)

	fmt.Println("===")
	fmt.Printf("%#+v\n", pid)
	fmt.Printf("%#+v\n%#+v\n", prevNS, targetNS)

	//	if !util.PathExists(sockPath) {
	time.Sleep(time.Second)
	return nil
}

func main() {
	err := Inject(765202)
	if err != nil {
		fmt.Println(err)
	}
}
