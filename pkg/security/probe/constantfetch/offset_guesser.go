// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && linux_bpf
// +build linux,linux_bpf

package constantfetch

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"

	manager "github.com/DataDog/ebpf-manager"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

const offsetGuesserUID = "security-og"

var (
	offsetGuesserMaps = []*manager.Map{
		{Name: "guessed_offsets"},
	}
)

type offsetGuesserStage struct {
	probes   []*manager.Probe
	guessers map[string]func() (uint64, error)
}

// OffsetGuesser defines an offset guesser object
type OffsetGuesser struct {
	config  *config.Config
	manager *manager.Manager
	res     map[string]uint64
	stages  []offsetGuesserStage
}

// NewOffsetGuesserFetcher returns a new OffsetGuesserFetcher
func NewOffsetGuesserFetcher(config *config.Config) *OffsetGuesser {
	og := &OffsetGuesser{
		config: config,
		manager: &manager.Manager{
			Maps: offsetGuesserMaps,
		},
		res: make(map[string]uint64),
	}

	// stage 0
	og.stages = append(og.stages, offsetGuesserStage{
		probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          offsetGuesserUID,
					EBPFFuncName: "kprobe_get_pid_task_numbers",
				},
			},
		},
		guessers: map[string]func() (uint64, error){
			OffsetNamePIDStructNumbers: og.guessPidNumbersOfsset,
		},
	})

	// stage 1
	og.stages = append(og.stages, offsetGuesserStage{
		probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          offsetGuesserUID,
					EBPFFuncName: "kprobe_get_pid_task_offset",
				},
			},
		},
		guessers: map[string]func() (uint64, error){
			OffsetNameTaskStructPIDStruct: og.guessTaskStructPidStructOffset,
		},
	})

	for _, stage := range og.stages {
		og.manager.Probes = append(og.manager.Probes, stage.probes...)
	}

	return og
}

func (og *OffsetGuesser) String() string {
	return "offset-guesser"
}

func (og *OffsetGuesser) guessPidNumbersOfsset() (uint64, error) {
	if _, err := os.ReadFile(utils.StatusPath(int32(utils.Getpid()))); err != nil {
		return ErrorSentinel, err
	}
	offsetMap, _, err := og.manager.GetMap("guessed_offsets")
	if err != nil || offsetMap == nil {
		return ErrorSentinel, errors.New("map not found")
	}

	var offset uint32
	key := uint32(0)
	if err := offsetMap.Lookup(key, &offset); err != nil {
		return ErrorSentinel, err
	}
	fmt.Printf(">>> guessPidNumbersOfsset: %d\n", offset)

	return uint64(offset), nil
}

func (og *OffsetGuesser) guessTaskStructPidStructOffset() (uint64, error) {
	catPath, err := exec.LookPath("cat")
	if err != nil {
		return ErrorSentinel, err
	}
	_ = exec.Command(catPath, "/proc/self/fdinfo/1").Run()

	offsetMap, _, err := og.manager.GetMap("guessed_offsets")
	if err != nil || offsetMap == nil {
		return ErrorSentinel, errors.New("map not found")
	}

	var offset uint32
	key := uint32(1)
	if err := offsetMap.Lookup(key, &offset); err != nil {
		return ErrorSentinel, err
	}
	fmt.Printf(">>> guessTaskStructPidStructOffset: %d\n", offset)

	return uint64(offset), nil
}

// AppendSizeofRequest appends a sizeof request
func (og *OffsetGuesser) AppendSizeofRequest(id, typeName string, headers ...string) {
}

// AppendOffsetofRequest appends an offset request
func (og *OffsetGuesser) AppendOffsetofRequest(id, typeName, fieldName string, headers ...string) {
	og.res[id] = ErrorSentinel
}

// FinishAndGetResults returns the results
func (og *OffsetGuesser) FinishAndGetResults() (map[string]uint64, error) {
	loader := ebpf.NewOffsetGuesserLoader(og.config)
	defer loader.Close()

	bytecodeReader, err := loader.Load()
	if err != nil {
		return og.res, err
	}
	defer bytecodeReader.Close()

	options := manager.Options{
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "pid_expected",
				Value: uint64(utils.Getpid()),
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	for _, probe := range probes.AllProbes() {
		options.ExcludedFunctions = append(options.ExcludedFunctions, probe.ProbeIdentificationPair.EBPFFuncName)
	}
	options.ExcludedFunctions = append(options.ExcludedFunctions, probes.GetAllTCProgramFunctions()...)

	if err := og.manager.InitWithOptions(bytecodeReader, options); err != nil {
		return og.res, err
	}

	if err := og.manager.Start(); err != nil {
		return og.res, err
	}

outer:
	for _, stage := range og.stages {
		var selectors []manager.ProbesSelector
		var allOf manager.AllOf
		for _, probe := range stage.probes {
			allOf.Selectors = append(allOf.Selectors, &manager.ProbeSelector{
				ProbeIdentificationPair: probe.ProbeIdentificationPair,
			})
		}
		selectors = append(selectors, &allOf)
		og.manager.UpdateActivatedProbes(selectors)

		for id, guess := range stage.guessers {
			var offset uint64
			offset, err = guess()
			if err != nil {
				break outer
			}
			og.res[id] = offset
		}
	}

	if err := og.manager.Stop(manager.CleanAll); err != nil {
		return og.res, err
	}

	return og.res, err
}
