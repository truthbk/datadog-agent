// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package uprobe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	manager "github.com/DataDog/ebpf-manager"
)

const DefaultMaxConcurrentUProbes = uint64(100)

var (
	ErrUProbeRuleMissingPath                 = errors.New("uprobe rule is missing a path value")
	ErrUProbeRuleInvalidPath                 = errors.New("uprobe rule has invalid path value")
	ErrUProbeRuleInvalidVersion              = errors.New("uprobe rule has invalid version value")
	ErrUProbeRuleInvalidFunctionName         = errors.New("uprobe rule has invalid function name value")
	ErrUProbeRuleInvalidOffset               = errors.New("uprobe rule has invalid offset value")
	ErrUProbeRuleMissingFunctionNameOrOffset = errors.New("uprobe rule requires either a function name or an offset value")
	ErrUProbeRuleInvalidArgumentExpression   = errors.New("uprobe rule has invalid argument expression")
	ErrMaxConcurrentUProbes                  = errors.New("max concurrent uprobe reached")
)

type UProbeManagerOptions struct {
	MaxConcurrentUProbes uint64
}

var uman *uprobeManager

type uprobeManager struct {
	lock             sync.Mutex
	options          UProbeManagerOptions
	allUProbes       map[uint64]*uprobe   // id to uprobe map
	ruleFilesUprobes map[string][]*uprobe // path to list of uprobe map
	containerUProbes map[uint32][]*uprobe // container pid one to uprobe map
	m                *manager.Manager
	uprobeFreeList   chan *uprobe
	nextRuleID       uint64
}

type uprobeDesc struct {
	Path         string
	Version      string
	FunctionName string
	OffsetStr    string
	Offset       uint64
}

type uprobeArg struct {
	txt    string
	parsed *UProbeArgumentExpression
}

type uprobe struct {
	desc   uprobeDesc
	args   []uprobeArg
	id     uint64
	ruleID uint64
	pID    manager.ProbeIdentificationPair
}

func newUProbe(id uint64) *uprobe {
	return &uprobe{
		id:   id,
		args: make([]uprobeArg, 5),
	}
}

func newUProbeArgs() *model.UProbeVulnArgs {
	args := &model.UProbeVulnArgs{}
	for i := 0; i < 5; i++ {
		args.Args[i].Tocheck = false
	}
	return args
}

func getNextRuleID() uint64 {
	id := uman.nextRuleID
	uman.nextRuleID++
	return id
}

func getUProbe() *uprobe {
	select {
	case up := <-uman.uprobeFreeList:
		return up
	default:
		return nil
	}
}

func putUProbe(up *uprobe) {
	if up != nil {
		uman.uprobeFreeList <- up
	}
}

func pushRuleArgs(ruleID uint64, vargs *model.UProbeVulnArgs) error {
	vulnargsMap, found, err := uman.m.GetMap("vulnargs")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("couldn't find vulnargs map")
	}

	err = vulnargsMap.Put(ruleID, vargs)
	if err != nil {
		return err
	}
	return nil
}

func Init(manager *manager.Manager, options UProbeManagerOptions) error {
	if uman == nil {
		uman = &uprobeManager{
			allUProbes:       make(map[uint64]*uprobe),
			ruleFilesUprobes: make(map[string][]*uprobe),
			containerUProbes: make(map[uint32][]*uprobe),
			m:                manager,
			options:          options,
		}

		if options.MaxConcurrentUProbes == 0 {
			uman.options.MaxConcurrentUProbes = DefaultMaxConcurrentUProbes
		}
		uman.uprobeFreeList = make(chan *uprobe, uman.options.MaxConcurrentUProbes)
		for i := uint64(0); i < uman.options.MaxConcurrentUProbes; i++ {
			putUProbe(newUProbe(i))
		}
	}
	return nil
}

func ResolveUProbeEventFields(event *model.UProbeEvent) {
	uman.lock.Lock()
	defer uman.lock.Unlock()

	if up, exists := uman.allUProbes[event.ID]; exists {
		event.Path = up.desc.Path
		event.Version = up.desc.Version
		event.FunctionName = up.desc.FunctionName
		event.Offset = up.desc.OffsetStr
		event.Arg1 = up.args[0].txt
		event.Arg2 = up.args[1].txt
		event.Arg3 = up.args[2].txt
		event.Arg4 = up.args[3].txt
		event.Arg5 = up.args[4].txt
	}
}

func CreateUProbeFromRules(rules []*rules.Rule) error {
	uman.lock.Lock()
	defer uman.lock.Unlock()

	for _, rule := range rules {
		up := getUProbe()
		if up == nil {
			return ErrMaxConcurrentUProbes
		}

		pathValues := rule.GetFieldValues("uprobe.path")
		if len(pathValues) == 0 {
			putUProbe(up)
			return ErrUProbeRuleMissingPath
		}
		pathValue, ok := pathValues[0].Value.(string)
		if !ok {
			putUProbe(up)
			return ErrUProbeRuleInvalidPath
		}

		var versionValue string
		versionValues := rule.GetFieldValues("uprobe.version")
		if len(versionValues) != 0 {
			versionValue, ok = versionValues[0].Value.(string)
			if !ok {
				putUProbe(up)
				return ErrUProbeRuleInvalidVersion
			}
		}

		var functionNameValue string
		functionNameValues := rule.GetFieldValues("uprobe.function_name")
		if len(functionNameValues) != 0 {
			functionNameValue, ok = functionNameValues[0].Value.(string)
			if !ok {
				putUProbe(up)
				return ErrUProbeRuleInvalidFunctionName
			}
		}

		var offsetValue string
		var offsetInt uint64
		offsetValues := rule.GetFieldValues("uprobe.offset")
		if len(offsetValues) != 0 {
			offsetValue, ok = offsetValues[0].Value.(string)
			if !ok {
				putUProbe(up)
				return ErrUProbeRuleInvalidOffset
			}
			var err error
			offsetInt, err = strconv.ParseUint(offsetValue, 0, 64)
			if err != nil {
				putUProbe(up)
				return ErrUProbeRuleInvalidOffset
			}
		}

		if len(functionNameValue) == 0 && len(offsetValue) == 0 {
			putUProbe(up)
			return ErrUProbeRuleMissingFunctionNameOrOffset
		}

		// parse optional argument expressions
		for i := 0; i < 5; i++ {
			seclKey := fmt.Sprintf("uprobe.arg%d", i+1)
			argValues := rule.GetFieldValues(seclKey)
			if len(argValues) == 0 {
				continue
			}

			var argValue string
			argValue, ok = argValues[0].Value.(string)
			if !ok {
				putUProbe(up)
				return ErrUProbeRuleInvalidArgumentExpression
			}

			var err error
			up.args[i].parsed, err = argParser.ParseString("", argValue)
			if err != nil || up.args[i].parsed == nil {
				putUProbe(up)
				return ErrUProbeRuleInvalidArgumentExpression
			}
			up.args[i].txt = argValue
		}

		vargs := newUProbeArgs()

		// push any valid argument value to the kernel map
		for i := 0; i < 5; i++ {
			if up.args[i].parsed == nil {
				continue
			}

			switch val := up.args[i].parsed.Arg.(type) {
			case UProbeU8Argument:
				fmt.Printf(">>>>>> [%d] got u8 arg: %d\n", i+1, val.Value)
				vargs.Args[i].Tocheck = true
				vargs.Args[i].Toderef = false
				vargs.Args[i].Len = 1
				vargs.Args[i].Offset = 0
				vargs.Args[i].Val[0] = val.Value
			case UProbeU16Argument:
				fmt.Printf(">>>>>> [%d] got u16 arg: %d\n", i+1, val.Value)
				vargs.Args[i].Tocheck = true
				vargs.Args[i].Toderef = false
				vargs.Args[i].Len = 2
				vargs.Args[i].Offset = 0
				model.ByteOrder.PutUint16(vargs.Args[i].Val[0:], val.Value)
			case UProbeU32Argument:
				fmt.Printf(">>>>>> [%d] got u32 arg: %d\n", i+1, val.Value)
				vargs.Args[i].Tocheck = true
				vargs.Args[i].Toderef = false
				vargs.Args[i].Len = 4
				vargs.Args[i].Offset = 0
				model.ByteOrder.PutUint32(vargs.Args[i].Val[0:], val.Value)
			case UProbeU64Argument:
				fmt.Printf(">>>>>> [%d] got u64 arg: %d\n", i+1, val.Value)
				vargs.Args[i].Tocheck = true
				vargs.Args[i].Toderef = false
				vargs.Args[i].Len = 8
				vargs.Args[i].Offset = 0
				model.ByteOrder.PutUint64(vargs.Args[i].Val[0:], val.Value)
			case UProbeStringArgument:
				fmt.Printf(">>>>>> [%d] got string arg: %s\n", i+1, val.Value)
				if len(val.Value) > model.UPROBE_MAX_CHECK_LEN {
					seclog.Warnf("uprobe argument string %s exceeds the maximum length of %d, skipping the rule\n", val.Value, model.UPROBE_MAX_CHECK_LEN)
					continue
				}
				vargs.Args[i].Tocheck = true
				vargs.Args[i].Toderef = true
				vargs.Args[i].Len = uint8(len(val.Value))
				vargs.Args[i].Offset = 0
				copy(vargs.Args[i].Val[:], val.Value)
			default:
				seclog.Errorf("uprobe argument has unknown type, shouldn't happen")
				continue
			}
		}

		ruleID := getNextRuleID()

		if err := pushRuleArgs(ruleID, vargs); err != nil {
			putUProbe(up)
			return err
		}

		up.desc.Path = pathValue
		up.desc.Version = versionValue
		up.desc.FunctionName = functionNameValue
		up.desc.OffsetStr = offsetValue
		up.desc.Offset = offsetInt
		up.ruleID = ruleID

		if err := attachProbe(uman.m, up); err != nil {
			putUProbe(up)
			return err
		}

		uman.allUProbes[up.id] = up
		uman.ruleFilesUprobes[up.desc.Path] = append(uman.ruleFilesUprobes[up.desc.Path], up)
	}

	return nil
}

func GetActivatedProbes() []manager.ProbesSelector {
	uman.lock.Lock()
	defer uman.lock.Unlock()

	selector := &manager.BestEffort{}

	for _, up := range uman.allUProbes {
		selector.Selectors = append(selector.Selectors, &manager.ProbeSelector{
			ProbeIdentificationPair: up.pID,
		})
	}

	return []manager.ProbesSelector{selector}
}

func HandleNewMountNamespace(event *model.NewMountNSEvent) error {
	uman.lock.Lock()
	defer uman.lock.Unlock()

	rootPath := utils.RootPath(int32(event.PidOne))

	for path, uProbesForPath := range uman.ruleFilesUprobes {
		fullPath := filepath.Join(rootPath, path)
		fInfo, err := os.Stat(fullPath)
		if err != nil || fInfo.IsDir() {
			continue
		}

		for _, up := range uProbesForPath {

			newUProbe := getUProbe()
			if newUProbe == nil {
				return ErrMaxConcurrentUProbes
			}

			newUProbe.desc.Path = fullPath
			newUProbe.desc.Version = up.desc.Version
			newUProbe.desc.FunctionName = up.desc.FunctionName
			newUProbe.desc.OffsetStr = up.desc.OffsetStr
			newUProbe.desc.Offset = up.desc.Offset
			newUProbe.ruleID = up.ruleID
			newUProbe.args = up.args[:]

			err := attachProbe(uman.m, newUProbe)
			if err != nil {
				putUProbe(newUProbe)
				seclog.Errorf("failed to attach container uprobe %s %s:%s err: %w", newUProbe.pID.UID, newUProbe.desc.Path, newUProbe.desc.FunctionName, err)
				continue
			}

			uman.allUProbes[newUProbe.id] = newUProbe
			uman.containerUProbes[event.PidOne] = append(uman.containerUProbes[event.PidOne], newUProbe)

			seclog.Infof("attached uprobe %s %s:%s", newUProbe.pID.UID, newUProbe.desc.Path, newUProbe.desc.FunctionName)
		}
	}

	return nil
}

func HandleProcessExit(event *model.ExitEvent) {
	uman.lock.Lock()
	defer uman.lock.Unlock()

	for _, up := range uman.containerUProbes[event.PIDContext.Tid] {
		if err := uman.m.DetachHook(up.pID); err != nil {
			seclog.Warnf("failed to detach uprobe %s %s:%s err: %w", up.pID.UID, up.desc.Path, up.desc.FunctionName, err)
		} else {
			seclog.Infof("detached uprobe %s %s:%s", up.pID.UID, up.desc.Path, up.desc.FunctionName)
		}
		delete(uman.allUProbes, up.id)
		putUProbe(up)
	}
	delete(uman.containerUProbes, event.PIDContext.Tid)
}
