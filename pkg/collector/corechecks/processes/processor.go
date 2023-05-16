// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package processes

import (
	"time"

	model "github.com/DataDog/agent-payload/v5/contimage"
	"github.com/DataDog/gopsutil/cpu"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var /* const */ (
	sourceAgent = "agent"
)

type processor struct {
	sender       aggregator.Sender
	hostInfo     *checks.HostInfo
	processes    *checks.ProcessData
	queue        chan *model.ContainerImage
	maxBatchSize int

	lastProcs   map[int32]*procutil.Process
	lastCPUTime cpu.TimesStat
	lastRun     time.Time
}

func newProcessor(sender aggregator.Sender, maxNbItem int, maxRetentionTime time.Duration) *processor {
	// TODO: figure out how to get global config to call CollectHostInfo
	// We can probably simplify it as we're running on the core agent, e.g. no need to perform gRPC call to validate hostname
	hostInfo, err := checks.CollectHostInfo(config.Datadog)
	if err != nil {
		log.Error("CAN'T COLLECT HOST INFO", err)
	}

	return &processor{
		processes:    checks.NewProcessData(config.Datadog),
		maxBatchSize: maxNbItem,
		hostInfo:     hostInfo,
		sender:       sender,
	}
}

var groupID int32

func nextGroupID() int32 {
	groupID++
	return groupID
}

func (p *processor) collectProcesses() {
	nextGroupID()

	start := time.Now()
	log.Info("Start collection", start)

	cpuTimes, err := cpu.Times(false)
	if err != nil {
		log.Error("ERROR COLLECTING CPU TIME")
		return
	}
	if len(cpuTimes) == 0 {
		log.Error("LEN(CPU_TIME)==0")
		return
	}

	procs, err := p.processes.Fetch()
	if err != nil {
		log.Info("ERROR: ", err)
	}
	printProcesses(procs)

	if p.lastProcs == nil {
		p.lastProcs = procs
		p.lastCPUTime = cpuTimes[0]
		p.lastRun = time.Now()

		return
	}

	procsByCtr := checks.FormatProcesses(procs, p.lastProcs, cpuTimes[0], p.lastCPUTime, p.lastRun)
	messages, totalProcs, totalContainers := checks.CreateProcCtrMessages(p.hostInfo, procsByCtr, nil, p.maxBatchSize, groupID)

	// TODO: send messages to DD intake
	log.Info("TOTAL PROCS: ", totalProcs)
	log.Info("TOTAL CTRS: ", totalContainers)
	log.Info("MESSAGES #:", len(messages))

	p.sender.ProcessData(messages)
}

func (p *processor) stop() {
	close(p.queue)
}
