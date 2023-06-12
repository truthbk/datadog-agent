// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.

//go:build windows
// +build windows

package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"reflect"
)

func (m *Model) GetIterator(field eval.Field) (eval.Iterator, error) {
	switch field {
	}
	return nil, &eval.ErrIteratorNotSupported{Field: field}
}
func (m *Model) GetEventTypes() []eval.EventType {
	return []eval.EventType{
		eval.EventType(""),
		eval.EventType("exec"),
	}
}
func (m *Model) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "event.timestamp":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveEventTimestamp(ev))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.cmdline":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.ExecWindows.CmdLine
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.ExecWindows.PathnameStr
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.ExecWindows.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFields() []eval.Field {
	return []eval.Field{
		"event.timestamp",
		"exec.cmdline",
		"exec.file.path",
		"exec.pid",
	}
}
func (ev *Event) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {
	case "event.timestamp":
		return int(ev.FieldHandlers.ResolveEventTimestamp(ev)), nil
	case "exec.cmdline":
		return ev.ExecWindows.CmdLine, nil
	case "exec.file.path":
		return ev.ExecWindows.PathnameStr, nil
	case "exec.pid":
		return int(ev.ExecWindows.Pid), nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldEventType(field eval.Field) (eval.EventType, error) {
	switch field {
	case "event.timestamp":
		return "", nil
	case "exec.cmdline":
		return "exec", nil
	case "exec.file.path":
		return "exec", nil
	case "exec.pid":
		return "exec", nil
	}
	return "", &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldType(field eval.Field) (reflect.Kind, error) {
	switch field {
	case "event.timestamp":
		return reflect.Int, nil
	case "exec.cmdline":
		return reflect.String, nil
	case "exec.file.path":
		return reflect.String, nil
	case "exec.pid":
		return reflect.Int, nil
	}
	return reflect.Invalid, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) SetFieldValue(field eval.Field, value interface{}) error {
	switch field {
	case "event.timestamp":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "TimestampRaw"}
		}
		ev.TimestampRaw = uint64(rv)
		return nil
	case "exec.cmdline":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ExecWindows.CmdLine"}
		}
		ev.ExecWindows.CmdLine = rv
		return nil
	case "exec.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ExecWindows.PathnameStr"}
		}
		ev.ExecWindows.PathnameStr = rv
		return nil
	case "exec.pid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "ExecWindows.Pid"}
		}
		ev.ExecWindows.Pid = uint32(rv)
		return nil
	}
	return &eval.ErrFieldNotFound{Field: field}
}
