// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.

//go:build linux
// +build linux

package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"net"
	"reflect"
)

func (m *Model) GetIterator(field eval.Field) (eval.Iterator, error) {
	switch field {
	}
	return nil, &eval.ErrIteratorNotSupported{Field: field}
}
func (m *Model) GetEventTypes() []eval.EventType {
	return []eval.EventType{
		eval.EventType("bind"),
		eval.EventType("bpf"),
		eval.EventType("capset"),
		eval.EventType("chmod"),
		eval.EventType("chown"),
		eval.EventType("dns"),
		eval.EventType("exec"),
		eval.EventType("exit"),
		eval.EventType("link"),
		eval.EventType("load_module"),
		eval.EventType("mkdir"),
		eval.EventType("mmap"),
		eval.EventType("mount"),
		eval.EventType("mprotect"),
		eval.EventType("open"),
		eval.EventType("ptrace"),
		eval.EventType("removexattr"),
		eval.EventType("rename"),
		eval.EventType("rmdir"),
		eval.EventType("selinux"),
		eval.EventType("setgid"),
		eval.EventType("setuid"),
		eval.EventType("setxattr"),
		eval.EventType("signal"),
		eval.EventType("splice"),
		eval.EventType("unlink"),
		eval.EventType("unload_module"),
		eval.EventType("utimes"),
	}
}
func (m *Model) GetEvaluator(field eval.Field, regID eval.RegisterID) (eval.Evaluator, error) {
	switch field {
	case "bind.addr.family":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Bind.AddrFamily)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.addr.ip":
		return &eval.CIDREvaluator{
			EvalFnc: func(ctx *eval.Context) net.IPNet {
				ev := ctx.Event.(*Event)
				return ev.Bind.Addr.IPNet
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.addr.port":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Bind.Addr.Port)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bind.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Bind.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.cmd":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.BPF.Cmd)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.map.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.BPF.Map.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.map.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.BPF.Map.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.attach_type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.BPF.Program.AttachType)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.helpers":
		return &eval.IntArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []int {
				ev := ctx.Event.(*Event)
				result := make([]int, len(ev.BPF.Program.Helpers))
				for i, v := range ev.BPF.Program.Helpers {
					result[i] = int(v)
				}
				return result
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.BPF.Program.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.tag":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.BPF.Program.Tag
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.prog.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.BPF.Program.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "bpf.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.BPF.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "capset.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Capset.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "capset.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Capset.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chmod.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chmod.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Chmod.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Chmod.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chmod.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Chmod.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chmod.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chmod.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveChownGID(ev, &ev.Chown)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveChownUID(ev, &ev.Chown)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chown.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chown.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Chown.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Chown.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "chown.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Chown.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "chown.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Chown.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.DNS.ID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.class":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.DNS.Class)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.count":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.DNS.Count)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.length":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.DNS.Size)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.name":
		return &eval.StringEvaluator{
			OpOverrides: eval.DNSNameCmp,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.DNS.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.name.length":
		return &eval.IntEvaluator{
			OpOverrides: eval.DNSNameCmp,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.DNS.Name)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "dns.question.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.DNS.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "event.async":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveAsync(ev)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exec.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exec.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exec.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exec.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.interpreter.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.interpreter.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exec.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exec.is_kworker":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.PIDContext.IsKworker
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exec.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exec.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exec.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.args_flags":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_options":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.argv0":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: 100 * eval.HandlerWeight,
		}, nil
	case "exit.cap_effective":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.CapEffective)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cap_permitted":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.CapPermitted)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.cause":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Cause)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.code":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Code)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.comm":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Comm
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.container.id":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.ContainerID
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.created_at":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exit.Process))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.EGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.envp":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.envs_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exit.Process)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.EUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return 0
				}
				return int(ev.Exit.Process.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.IsNotKworker() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.FSGroup
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.FSUser
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.Group
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return false
				}
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.interpreter.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return 0
				}
				return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.interpreter.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				if !ev.Exit.Process.HasInterpreter() {
					return ""
				}
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "exit.is_kworker":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.PIDContext.IsKworker
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.is_thread":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.IsThread
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PIDContext.Pid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.ppid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PPid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.PIDContext.Tid)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.tty_name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.TTYName
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Exit.Process.Credentials.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "exit.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Exit.Process.Credentials.User
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Target))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Target)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Target))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Link.Target.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Target.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Link.Target.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Source))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Source)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Source))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Link.Source.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.Source.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "link.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Link.Source.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "link.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Link.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.args":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveModuleArgs(ev, &ev.LoadModule)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.args_truncated":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.LoadModule.ArgsTruncated
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.argv":
		return &eval.StringArrayEvaluator{
			EvalFnc: func(ctx *eval.Context) []string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveModuleArgv(ev, &ev.LoadModule)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.LoadModule.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.LoadModule.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.LoadModule.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.LoadModule.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.LoadModule.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "load_module.loaded_from_memory":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.LoadModule.LoadedFromMemory
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.LoadModule.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "load_module.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.LoadModule.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Mkdir.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Mkdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Mkdir.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Mkdir.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mkdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Mkdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mkdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mkdir.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.MMap.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.MMap.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.MMap.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.MMap.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.MMap.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mmap.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return ev.MMap.Flags
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return ev.MMap.Protection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mmap.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MMap.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mount.fs_type":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.Mount.Mount.FSType
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mount.mountpoint.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveMountPointPath(ev, &ev.Mount)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mount.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Mount.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mount.source.path":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveMountSourcePath(ev, &ev.Mount)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "mprotect.req_protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return ev.MProtect.ReqProtection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mprotect.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.MProtect.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "mprotect.vm_protection":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return ev.MProtect.VMProtection
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Open.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Open.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Open.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Open.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Open.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "open.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.Flags)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "open.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Open.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.request":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.PTrace.Request)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "ptrace.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.PTrace.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveXAttrName(ev, &ev.RemoveXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveXAttrNamespace(ev, &ev.RemoveXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.RemoveXAttr.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.RemoveXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.RemoveXAttr.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.RemoveXAttr.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "removexattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.RemoveXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "removexattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.RemoveXAttr.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.New))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.New)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.New))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rename.New.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.destination.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.New.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.destination.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rename.New.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.Old))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.Old)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.Old))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rename.Old.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.Old.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rename.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rename.Old.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rename.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rename.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rmdir.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rmdir.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Rmdir.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rmdir.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "rmdir.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rmdir.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "rmdir.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Rmdir.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.bool.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSELinuxBoolName(ev, &ev.SELinux)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "selinux.bool.state":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.SELinux.BoolChangeValue
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.bool_commit.state":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.SELinux.BoolCommitValue
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "selinux.enforce.status":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.SELinux.EnforceStatus
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.egid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetGID.EGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.egroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetgidEGroup(ev, &ev.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setgid.fsgid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetGID.FSGID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.fsgroup":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetgidFSGroup(ev, &ev.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setgid.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetGID.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setgid.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetgidGroup(ev, &ev.SetGID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.euid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetUID.EUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.euser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetuidEUser(ev, &ev.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.fsuid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetUID.FSUID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.fsuser":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetuidFSUser(ev, &ev.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setuid.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetUID.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setuid.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveSetuidUser(ev, &ev.SetUID)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.destination.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveXAttrName(ev, &ev.SetXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.destination.namespace":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveXAttrNamespace(ev, &ev.SetXAttr)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.SetXAttr.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.SetXAttr.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.SetXAttr.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.SetXAttr.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "setxattr.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.SetXAttr.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "setxattr.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.SetXAttr.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.pid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Signal.PID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Signal.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "signal.type":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Signal.Type)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Splice.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Splice.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Splice.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Splice.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Splice.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "splice.pipe_entry_flag":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.PipeEntryFlag)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.pipe_exit_flag":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.PipeExitFlag)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "splice.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Splice.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Unlink.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Unlink.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Unlink.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Unlink.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Unlink.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "unlink.flags":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.Flags)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unlink.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Unlink.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unload_module.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.UnloadModule.Name
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "unload_module.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.UnloadModule.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.change_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.CTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.filesystem":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.gid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.GID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.group":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.in_upper_layer":
		return &eval.BoolEvaluator{
			EvalFnc: func(ctx *eval.Context) bool {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.inode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.PathKey.Inode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.mode":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.Mode)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.modification_time":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.MTime)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.mount_id":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.PathKey.MountID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.name":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.name.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkBasename,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Utimes.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.package.name":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageName(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.package.source_version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.package.version":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.path":
		return &eval.StringEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFilePath(ev, &ev.Utimes.File)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.path.length":
		return &eval.IntEvaluator{
			OpOverrides: ProcessSymlinkPathname,
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Utimes.File))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.rights":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.FieldHandlers.ResolveRights(ev, &ev.Utimes.File.FileFields))
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.file.uid":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.File.FileFields.UID)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	case "utimes.file.user":
		return &eval.StringEvaluator{
			EvalFnc: func(ctx *eval.Context) string {
				ev := ctx.Event.(*Event)
				return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Utimes.File.FileFields)
			},
			Field:  field,
			Weight: eval.HandlerWeight,
		}, nil
	case "utimes.retval":
		return &eval.IntEvaluator{
			EvalFnc: func(ctx *eval.Context) int {
				ev := ctx.Event.(*Event)
				return int(ev.Utimes.SyscallEvent.Retval)
			},
			Field:  field,
			Weight: eval.FunctionWeight,
		}, nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFields() []eval.Field {
	return []eval.Field{
		"bind.addr.family",
		"bind.addr.ip",
		"bind.addr.port",
		"bind.retval",
		"bpf.cmd",
		"bpf.map.name",
		"bpf.map.type",
		"bpf.prog.attach_type",
		"bpf.prog.helpers",
		"bpf.prog.name",
		"bpf.prog.tag",
		"bpf.prog.type",
		"bpf.retval",
		"capset.cap_effective",
		"capset.cap_permitted",
		"chmod.file.change_time",
		"chmod.file.destination.mode",
		"chmod.file.destination.rights",
		"chmod.file.filesystem",
		"chmod.file.gid",
		"chmod.file.group",
		"chmod.file.in_upper_layer",
		"chmod.file.inode",
		"chmod.file.mode",
		"chmod.file.modification_time",
		"chmod.file.mount_id",
		"chmod.file.name",
		"chmod.file.name.length",
		"chmod.file.package.name",
		"chmod.file.package.source_version",
		"chmod.file.package.version",
		"chmod.file.path",
		"chmod.file.path.length",
		"chmod.file.rights",
		"chmod.file.uid",
		"chmod.file.user",
		"chmod.retval",
		"chown.file.change_time",
		"chown.file.destination.gid",
		"chown.file.destination.group",
		"chown.file.destination.uid",
		"chown.file.destination.user",
		"chown.file.filesystem",
		"chown.file.gid",
		"chown.file.group",
		"chown.file.in_upper_layer",
		"chown.file.inode",
		"chown.file.mode",
		"chown.file.modification_time",
		"chown.file.mount_id",
		"chown.file.name",
		"chown.file.name.length",
		"chown.file.package.name",
		"chown.file.package.source_version",
		"chown.file.package.version",
		"chown.file.path",
		"chown.file.path.length",
		"chown.file.rights",
		"chown.file.uid",
		"chown.file.user",
		"chown.retval",
		"dns.id",
		"dns.question.class",
		"dns.question.count",
		"dns.question.length",
		"dns.question.name",
		"dns.question.name.length",
		"dns.question.type",
		"event.async",
		"exec.args",
		"exec.args_flags",
		"exec.args_options",
		"exec.args_truncated",
		"exec.argv",
		"exec.argv0",
		"exec.cap_effective",
		"exec.cap_permitted",
		"exec.comm",
		"exec.container.id",
		"exec.created_at",
		"exec.egid",
		"exec.egroup",
		"exec.envp",
		"exec.envs",
		"exec.envs_truncated",
		"exec.euid",
		"exec.euser",
		"exec.file.change_time",
		"exec.file.filesystem",
		"exec.file.gid",
		"exec.file.group",
		"exec.file.in_upper_layer",
		"exec.file.inode",
		"exec.file.mode",
		"exec.file.modification_time",
		"exec.file.mount_id",
		"exec.file.name",
		"exec.file.name.length",
		"exec.file.package.name",
		"exec.file.package.source_version",
		"exec.file.package.version",
		"exec.file.path",
		"exec.file.path.length",
		"exec.file.rights",
		"exec.file.uid",
		"exec.file.user",
		"exec.fsgid",
		"exec.fsgroup",
		"exec.fsuid",
		"exec.fsuser",
		"exec.gid",
		"exec.group",
		"exec.interpreter.file.change_time",
		"exec.interpreter.file.filesystem",
		"exec.interpreter.file.gid",
		"exec.interpreter.file.group",
		"exec.interpreter.file.in_upper_layer",
		"exec.interpreter.file.inode",
		"exec.interpreter.file.mode",
		"exec.interpreter.file.modification_time",
		"exec.interpreter.file.mount_id",
		"exec.interpreter.file.name",
		"exec.interpreter.file.name.length",
		"exec.interpreter.file.package.name",
		"exec.interpreter.file.package.source_version",
		"exec.interpreter.file.package.version",
		"exec.interpreter.file.path",
		"exec.interpreter.file.path.length",
		"exec.interpreter.file.rights",
		"exec.interpreter.file.uid",
		"exec.interpreter.file.user",
		"exec.is_kworker",
		"exec.is_thread",
		"exec.pid",
		"exec.ppid",
		"exec.tid",
		"exec.tty_name",
		"exec.uid",
		"exec.user",
		"exit.args",
		"exit.args_flags",
		"exit.args_options",
		"exit.args_truncated",
		"exit.argv",
		"exit.argv0",
		"exit.cap_effective",
		"exit.cap_permitted",
		"exit.cause",
		"exit.code",
		"exit.comm",
		"exit.container.id",
		"exit.created_at",
		"exit.egid",
		"exit.egroup",
		"exit.envp",
		"exit.envs",
		"exit.envs_truncated",
		"exit.euid",
		"exit.euser",
		"exit.file.change_time",
		"exit.file.filesystem",
		"exit.file.gid",
		"exit.file.group",
		"exit.file.in_upper_layer",
		"exit.file.inode",
		"exit.file.mode",
		"exit.file.modification_time",
		"exit.file.mount_id",
		"exit.file.name",
		"exit.file.name.length",
		"exit.file.package.name",
		"exit.file.package.source_version",
		"exit.file.package.version",
		"exit.file.path",
		"exit.file.path.length",
		"exit.file.rights",
		"exit.file.uid",
		"exit.file.user",
		"exit.fsgid",
		"exit.fsgroup",
		"exit.fsuid",
		"exit.fsuser",
		"exit.gid",
		"exit.group",
		"exit.interpreter.file.change_time",
		"exit.interpreter.file.filesystem",
		"exit.interpreter.file.gid",
		"exit.interpreter.file.group",
		"exit.interpreter.file.in_upper_layer",
		"exit.interpreter.file.inode",
		"exit.interpreter.file.mode",
		"exit.interpreter.file.modification_time",
		"exit.interpreter.file.mount_id",
		"exit.interpreter.file.name",
		"exit.interpreter.file.name.length",
		"exit.interpreter.file.package.name",
		"exit.interpreter.file.package.source_version",
		"exit.interpreter.file.package.version",
		"exit.interpreter.file.path",
		"exit.interpreter.file.path.length",
		"exit.interpreter.file.rights",
		"exit.interpreter.file.uid",
		"exit.interpreter.file.user",
		"exit.is_kworker",
		"exit.is_thread",
		"exit.pid",
		"exit.ppid",
		"exit.tid",
		"exit.tty_name",
		"exit.uid",
		"exit.user",
		"link.file.change_time",
		"link.file.destination.change_time",
		"link.file.destination.filesystem",
		"link.file.destination.gid",
		"link.file.destination.group",
		"link.file.destination.in_upper_layer",
		"link.file.destination.inode",
		"link.file.destination.mode",
		"link.file.destination.modification_time",
		"link.file.destination.mount_id",
		"link.file.destination.name",
		"link.file.destination.name.length",
		"link.file.destination.package.name",
		"link.file.destination.package.source_version",
		"link.file.destination.package.version",
		"link.file.destination.path",
		"link.file.destination.path.length",
		"link.file.destination.rights",
		"link.file.destination.uid",
		"link.file.destination.user",
		"link.file.filesystem",
		"link.file.gid",
		"link.file.group",
		"link.file.in_upper_layer",
		"link.file.inode",
		"link.file.mode",
		"link.file.modification_time",
		"link.file.mount_id",
		"link.file.name",
		"link.file.name.length",
		"link.file.package.name",
		"link.file.package.source_version",
		"link.file.package.version",
		"link.file.path",
		"link.file.path.length",
		"link.file.rights",
		"link.file.uid",
		"link.file.user",
		"link.retval",
		"load_module.args",
		"load_module.args_truncated",
		"load_module.argv",
		"load_module.file.change_time",
		"load_module.file.filesystem",
		"load_module.file.gid",
		"load_module.file.group",
		"load_module.file.in_upper_layer",
		"load_module.file.inode",
		"load_module.file.mode",
		"load_module.file.modification_time",
		"load_module.file.mount_id",
		"load_module.file.name",
		"load_module.file.name.length",
		"load_module.file.package.name",
		"load_module.file.package.source_version",
		"load_module.file.package.version",
		"load_module.file.path",
		"load_module.file.path.length",
		"load_module.file.rights",
		"load_module.file.uid",
		"load_module.file.user",
		"load_module.loaded_from_memory",
		"load_module.name",
		"load_module.retval",
		"mkdir.file.change_time",
		"mkdir.file.destination.mode",
		"mkdir.file.destination.rights",
		"mkdir.file.filesystem",
		"mkdir.file.gid",
		"mkdir.file.group",
		"mkdir.file.in_upper_layer",
		"mkdir.file.inode",
		"mkdir.file.mode",
		"mkdir.file.modification_time",
		"mkdir.file.mount_id",
		"mkdir.file.name",
		"mkdir.file.name.length",
		"mkdir.file.package.name",
		"mkdir.file.package.source_version",
		"mkdir.file.package.version",
		"mkdir.file.path",
		"mkdir.file.path.length",
		"mkdir.file.rights",
		"mkdir.file.uid",
		"mkdir.file.user",
		"mkdir.retval",
		"mmap.file.change_time",
		"mmap.file.filesystem",
		"mmap.file.gid",
		"mmap.file.group",
		"mmap.file.in_upper_layer",
		"mmap.file.inode",
		"mmap.file.mode",
		"mmap.file.modification_time",
		"mmap.file.mount_id",
		"mmap.file.name",
		"mmap.file.name.length",
		"mmap.file.package.name",
		"mmap.file.package.source_version",
		"mmap.file.package.version",
		"mmap.file.path",
		"mmap.file.path.length",
		"mmap.file.rights",
		"mmap.file.uid",
		"mmap.file.user",
		"mmap.flags",
		"mmap.protection",
		"mmap.retval",
		"mount.fs_type",
		"mount.mountpoint.path",
		"mount.retval",
		"mount.source.path",
		"mprotect.req_protection",
		"mprotect.retval",
		"mprotect.vm_protection",
		"open.file.change_time",
		"open.file.destination.mode",
		"open.file.filesystem",
		"open.file.gid",
		"open.file.group",
		"open.file.in_upper_layer",
		"open.file.inode",
		"open.file.mode",
		"open.file.modification_time",
		"open.file.mount_id",
		"open.file.name",
		"open.file.name.length",
		"open.file.package.name",
		"open.file.package.source_version",
		"open.file.package.version",
		"open.file.path",
		"open.file.path.length",
		"open.file.rights",
		"open.file.uid",
		"open.file.user",
		"open.flags",
		"open.retval",
		"ptrace.request",
		"ptrace.retval",
		"removexattr.file.change_time",
		"removexattr.file.destination.name",
		"removexattr.file.destination.namespace",
		"removexattr.file.filesystem",
		"removexattr.file.gid",
		"removexattr.file.group",
		"removexattr.file.in_upper_layer",
		"removexattr.file.inode",
		"removexattr.file.mode",
		"removexattr.file.modification_time",
		"removexattr.file.mount_id",
		"removexattr.file.name",
		"removexattr.file.name.length",
		"removexattr.file.package.name",
		"removexattr.file.package.source_version",
		"removexattr.file.package.version",
		"removexattr.file.path",
		"removexattr.file.path.length",
		"removexattr.file.rights",
		"removexattr.file.uid",
		"removexattr.file.user",
		"removexattr.retval",
		"rename.file.change_time",
		"rename.file.destination.change_time",
		"rename.file.destination.filesystem",
		"rename.file.destination.gid",
		"rename.file.destination.group",
		"rename.file.destination.in_upper_layer",
		"rename.file.destination.inode",
		"rename.file.destination.mode",
		"rename.file.destination.modification_time",
		"rename.file.destination.mount_id",
		"rename.file.destination.name",
		"rename.file.destination.name.length",
		"rename.file.destination.package.name",
		"rename.file.destination.package.source_version",
		"rename.file.destination.package.version",
		"rename.file.destination.path",
		"rename.file.destination.path.length",
		"rename.file.destination.rights",
		"rename.file.destination.uid",
		"rename.file.destination.user",
		"rename.file.filesystem",
		"rename.file.gid",
		"rename.file.group",
		"rename.file.in_upper_layer",
		"rename.file.inode",
		"rename.file.mode",
		"rename.file.modification_time",
		"rename.file.mount_id",
		"rename.file.name",
		"rename.file.name.length",
		"rename.file.package.name",
		"rename.file.package.source_version",
		"rename.file.package.version",
		"rename.file.path",
		"rename.file.path.length",
		"rename.file.rights",
		"rename.file.uid",
		"rename.file.user",
		"rename.retval",
		"rmdir.file.change_time",
		"rmdir.file.filesystem",
		"rmdir.file.gid",
		"rmdir.file.group",
		"rmdir.file.in_upper_layer",
		"rmdir.file.inode",
		"rmdir.file.mode",
		"rmdir.file.modification_time",
		"rmdir.file.mount_id",
		"rmdir.file.name",
		"rmdir.file.name.length",
		"rmdir.file.package.name",
		"rmdir.file.package.source_version",
		"rmdir.file.package.version",
		"rmdir.file.path",
		"rmdir.file.path.length",
		"rmdir.file.rights",
		"rmdir.file.uid",
		"rmdir.file.user",
		"rmdir.retval",
		"selinux.bool.name",
		"selinux.bool.state",
		"selinux.bool_commit.state",
		"selinux.enforce.status",
		"setgid.egid",
		"setgid.egroup",
		"setgid.fsgid",
		"setgid.fsgroup",
		"setgid.gid",
		"setgid.group",
		"setuid.euid",
		"setuid.euser",
		"setuid.fsuid",
		"setuid.fsuser",
		"setuid.uid",
		"setuid.user",
		"setxattr.file.change_time",
		"setxattr.file.destination.name",
		"setxattr.file.destination.namespace",
		"setxattr.file.filesystem",
		"setxattr.file.gid",
		"setxattr.file.group",
		"setxattr.file.in_upper_layer",
		"setxattr.file.inode",
		"setxattr.file.mode",
		"setxattr.file.modification_time",
		"setxattr.file.mount_id",
		"setxattr.file.name",
		"setxattr.file.name.length",
		"setxattr.file.package.name",
		"setxattr.file.package.source_version",
		"setxattr.file.package.version",
		"setxattr.file.path",
		"setxattr.file.path.length",
		"setxattr.file.rights",
		"setxattr.file.uid",
		"setxattr.file.user",
		"setxattr.retval",
		"signal.pid",
		"signal.retval",
		"signal.type",
		"splice.file.change_time",
		"splice.file.filesystem",
		"splice.file.gid",
		"splice.file.group",
		"splice.file.in_upper_layer",
		"splice.file.inode",
		"splice.file.mode",
		"splice.file.modification_time",
		"splice.file.mount_id",
		"splice.file.name",
		"splice.file.name.length",
		"splice.file.package.name",
		"splice.file.package.source_version",
		"splice.file.package.version",
		"splice.file.path",
		"splice.file.path.length",
		"splice.file.rights",
		"splice.file.uid",
		"splice.file.user",
		"splice.pipe_entry_flag",
		"splice.pipe_exit_flag",
		"splice.retval",
		"unlink.file.change_time",
		"unlink.file.filesystem",
		"unlink.file.gid",
		"unlink.file.group",
		"unlink.file.in_upper_layer",
		"unlink.file.inode",
		"unlink.file.mode",
		"unlink.file.modification_time",
		"unlink.file.mount_id",
		"unlink.file.name",
		"unlink.file.name.length",
		"unlink.file.package.name",
		"unlink.file.package.source_version",
		"unlink.file.package.version",
		"unlink.file.path",
		"unlink.file.path.length",
		"unlink.file.rights",
		"unlink.file.uid",
		"unlink.file.user",
		"unlink.flags",
		"unlink.retval",
		"unload_module.name",
		"unload_module.retval",
		"utimes.file.change_time",
		"utimes.file.filesystem",
		"utimes.file.gid",
		"utimes.file.group",
		"utimes.file.in_upper_layer",
		"utimes.file.inode",
		"utimes.file.mode",
		"utimes.file.modification_time",
		"utimes.file.mount_id",
		"utimes.file.name",
		"utimes.file.name.length",
		"utimes.file.package.name",
		"utimes.file.package.source_version",
		"utimes.file.package.version",
		"utimes.file.path",
		"utimes.file.path.length",
		"utimes.file.rights",
		"utimes.file.uid",
		"utimes.file.user",
		"utimes.retval",
	}
}
func (ev *Event) GetFieldValue(field eval.Field) (interface{}, error) {
	switch field {
	case "bind.addr.family":
		return int(ev.Bind.AddrFamily), nil
	case "bind.addr.ip":
		return ev.Bind.Addr.IPNet, nil
	case "bind.addr.port":
		return int(ev.Bind.Addr.Port), nil
	case "bind.retval":
		return int(ev.Bind.SyscallEvent.Retval), nil
	case "bpf.cmd":
		return int(ev.BPF.Cmd), nil
	case "bpf.map.name":
		return ev.BPF.Map.Name, nil
	case "bpf.map.type":
		return int(ev.BPF.Map.Type), nil
	case "bpf.prog.attach_type":
		return int(ev.BPF.Program.AttachType), nil
	case "bpf.prog.helpers":
		result := make([]int, len(ev.BPF.Program.Helpers))
		for i, v := range ev.BPF.Program.Helpers {
			result[i] = int(v)
		}
		return result, nil
	case "bpf.prog.name":
		return ev.BPF.Program.Name, nil
	case "bpf.prog.tag":
		return ev.BPF.Program.Tag, nil
	case "bpf.prog.type":
		return int(ev.BPF.Program.Type), nil
	case "bpf.retval":
		return int(ev.BPF.SyscallEvent.Retval), nil
	case "capset.cap_effective":
		return int(ev.Capset.CapEffective), nil
	case "capset.cap_permitted":
		return int(ev.Capset.CapPermitted), nil
	case "chmod.file.change_time":
		return int(ev.Chmod.File.FileFields.CTime), nil
	case "chmod.file.destination.mode":
		return int(ev.Chmod.Mode), nil
	case "chmod.file.destination.rights":
		return int(ev.Chmod.Mode), nil
	case "chmod.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Chmod.File), nil
	case "chmod.file.gid":
		return int(ev.Chmod.File.FileFields.GID), nil
	case "chmod.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Chmod.File.FileFields), nil
	case "chmod.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Chmod.File.FileFields), nil
	case "chmod.file.inode":
		return int(ev.Chmod.File.FileFields.PathKey.Inode), nil
	case "chmod.file.mode":
		return int(ev.Chmod.File.FileFields.Mode), nil
	case "chmod.file.modification_time":
		return int(ev.Chmod.File.FileFields.MTime), nil
	case "chmod.file.mount_id":
		return int(ev.Chmod.File.FileFields.PathKey.MountID), nil
	case "chmod.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chmod.File), nil
	case "chmod.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chmod.File), nil
	case "chmod.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Chmod.File), nil
	case "chmod.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Chmod.File), nil
	case "chmod.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Chmod.File), nil
	case "chmod.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chmod.File), nil
	case "chmod.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chmod.File), nil
	case "chmod.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Chmod.File.FileFields)), nil
	case "chmod.file.uid":
		return int(ev.Chmod.File.FileFields.UID), nil
	case "chmod.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Chmod.File.FileFields), nil
	case "chmod.retval":
		return int(ev.Chmod.SyscallEvent.Retval), nil
	case "chown.file.change_time":
		return int(ev.Chown.File.FileFields.CTime), nil
	case "chown.file.destination.gid":
		return int(ev.Chown.GID), nil
	case "chown.file.destination.group":
		return ev.FieldHandlers.ResolveChownGID(ev, &ev.Chown), nil
	case "chown.file.destination.uid":
		return int(ev.Chown.UID), nil
	case "chown.file.destination.user":
		return ev.FieldHandlers.ResolveChownUID(ev, &ev.Chown), nil
	case "chown.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Chown.File), nil
	case "chown.file.gid":
		return int(ev.Chown.File.FileFields.GID), nil
	case "chown.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Chown.File.FileFields), nil
	case "chown.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Chown.File.FileFields), nil
	case "chown.file.inode":
		return int(ev.Chown.File.FileFields.PathKey.Inode), nil
	case "chown.file.mode":
		return int(ev.Chown.File.FileFields.Mode), nil
	case "chown.file.modification_time":
		return int(ev.Chown.File.FileFields.MTime), nil
	case "chown.file.mount_id":
		return int(ev.Chown.File.FileFields.PathKey.MountID), nil
	case "chown.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chown.File), nil
	case "chown.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Chown.File), nil
	case "chown.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Chown.File), nil
	case "chown.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Chown.File), nil
	case "chown.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Chown.File), nil
	case "chown.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chown.File), nil
	case "chown.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Chown.File), nil
	case "chown.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Chown.File.FileFields)), nil
	case "chown.file.uid":
		return int(ev.Chown.File.FileFields.UID), nil
	case "chown.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Chown.File.FileFields), nil
	case "chown.retval":
		return int(ev.Chown.SyscallEvent.Retval), nil
	case "dns.id":
		return int(ev.DNS.ID), nil
	case "dns.question.class":
		return int(ev.DNS.Class), nil
	case "dns.question.count":
		return int(ev.DNS.Count), nil
	case "dns.question.length":
		return int(ev.DNS.Size), nil
	case "dns.question.name":
		return ev.DNS.Name, nil
	case "dns.question.name.length":
		return len(ev.DNS.Name), nil
	case "dns.question.type":
		return int(ev.DNS.Type), nil
	case "event.async":
		return ev.FieldHandlers.ResolveAsync(ev), nil
	case "exec.args":
		return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exec.Process), nil
	case "exec.args_flags":
		return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exec.Process), nil
	case "exec.args_options":
		return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exec.Process), nil
	case "exec.args_truncated":
		return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exec.Process), nil
	case "exec.argv":
		return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exec.Process), nil
	case "exec.argv0":
		return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exec.Process), nil
	case "exec.cap_effective":
		return int(ev.Exec.Process.Credentials.CapEffective), nil
	case "exec.cap_permitted":
		return int(ev.Exec.Process.Credentials.CapPermitted), nil
	case "exec.comm":
		return ev.Exec.Process.Comm, nil
	case "exec.container.id":
		return ev.Exec.Process.ContainerID, nil
	case "exec.created_at":
		return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exec.Process)), nil
	case "exec.egid":
		return int(ev.Exec.Process.Credentials.EGID), nil
	case "exec.egroup":
		return ev.Exec.Process.Credentials.EGroup, nil
	case "exec.envp":
		return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exec.Process), nil
	case "exec.envs":
		return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exec.Process), nil
	case "exec.envs_truncated":
		return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exec.Process), nil
	case "exec.euid":
		return int(ev.Exec.Process.Credentials.EUID), nil
	case "exec.euser":
		return ev.Exec.Process.Credentials.EUser, nil
	case "exec.file.change_time":
		return int(ev.Exec.Process.FileEvent.FileFields.CTime), nil
	case "exec.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.gid":
		return int(ev.Exec.Process.FileEvent.FileFields.GID), nil
	case "exec.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.file.inode":
		return int(ev.Exec.Process.FileEvent.FileFields.PathKey.Inode), nil
	case "exec.file.mode":
		return int(ev.Exec.Process.FileEvent.FileFields.Mode), nil
	case "exec.file.modification_time":
		return int(ev.Exec.Process.FileEvent.FileFields.MTime), nil
	case "exec.file.mount_id":
		return int(ev.Exec.Process.FileEvent.FileFields.PathKey.MountID), nil
	case "exec.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent), nil
	case "exec.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.FileEvent.FileFields)), nil
	case "exec.file.uid":
		return int(ev.Exec.Process.FileEvent.FileFields.UID), nil
	case "exec.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.FileEvent.FileFields), nil
	case "exec.fsgid":
		return int(ev.Exec.Process.Credentials.FSGID), nil
	case "exec.fsgroup":
		return ev.Exec.Process.Credentials.FSGroup, nil
	case "exec.fsuid":
		return int(ev.Exec.Process.Credentials.FSUID), nil
	case "exec.fsuser":
		return ev.Exec.Process.Credentials.FSUser, nil
	case "exec.gid":
		return int(ev.Exec.Process.Credentials.GID), nil
	case "exec.group":
		return ev.Exec.Process.Credentials.Group, nil
	case "exec.interpreter.file.change_time":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime), nil
	case "exec.interpreter.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.gid":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID), nil
	case "exec.interpreter.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.interpreter.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.interpreter.file.inode":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode), nil
	case "exec.interpreter.file.mode":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode), nil
	case "exec.interpreter.file.modification_time":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime), nil
	case "exec.interpreter.file.mount_id":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID), nil
	case "exec.interpreter.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.LinuxBinprm.FileEvent), nil
	case "exec.interpreter.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields)), nil
	case "exec.interpreter.file.uid":
		return int(ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID), nil
	case "exec.interpreter.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exec.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exec.is_kworker":
		return ev.Exec.Process.PIDContext.IsKworker, nil
	case "exec.is_thread":
		return ev.Exec.Process.IsThread, nil
	case "exec.pid":
		return int(ev.Exec.Process.PIDContext.Pid), nil
	case "exec.ppid":
		return int(ev.Exec.Process.PPid), nil
	case "exec.tid":
		return int(ev.Exec.Process.PIDContext.Tid), nil
	case "exec.tty_name":
		return ev.Exec.Process.TTYName, nil
	case "exec.uid":
		return int(ev.Exec.Process.Credentials.UID), nil
	case "exec.user":
		return ev.Exec.Process.Credentials.User, nil
	case "exit.args":
		return ev.FieldHandlers.ResolveProcessArgs(ev, ev.Exit.Process), nil
	case "exit.args_flags":
		return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exit.Process), nil
	case "exit.args_options":
		return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exit.Process), nil
	case "exit.args_truncated":
		return ev.FieldHandlers.ResolveProcessArgsTruncated(ev, ev.Exit.Process), nil
	case "exit.argv":
		return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exit.Process), nil
	case "exit.argv0":
		return ev.FieldHandlers.ResolveProcessArgv0(ev, ev.Exit.Process), nil
	case "exit.cap_effective":
		return int(ev.Exit.Process.Credentials.CapEffective), nil
	case "exit.cap_permitted":
		return int(ev.Exit.Process.Credentials.CapPermitted), nil
	case "exit.cause":
		return int(ev.Exit.Cause), nil
	case "exit.code":
		return int(ev.Exit.Code), nil
	case "exit.comm":
		return ev.Exit.Process.Comm, nil
	case "exit.container.id":
		return ev.Exit.Process.ContainerID, nil
	case "exit.created_at":
		return int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exit.Process)), nil
	case "exit.egid":
		return int(ev.Exit.Process.Credentials.EGID), nil
	case "exit.egroup":
		return ev.Exit.Process.Credentials.EGroup, nil
	case "exit.envp":
		return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exit.Process), nil
	case "exit.envs":
		return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exit.Process), nil
	case "exit.envs_truncated":
		return ev.FieldHandlers.ResolveProcessEnvsTruncated(ev, ev.Exit.Process), nil
	case "exit.euid":
		return int(ev.Exit.Process.Credentials.EUID), nil
	case "exit.euser":
		return ev.Exit.Process.Credentials.EUser, nil
	case "exit.file.change_time":
		return int(ev.Exit.Process.FileEvent.FileFields.CTime), nil
	case "exit.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.gid":
		return int(ev.Exit.Process.FileEvent.FileFields.GID), nil
	case "exit.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.file.inode":
		return int(ev.Exit.Process.FileEvent.FileFields.PathKey.Inode), nil
	case "exit.file.mode":
		return int(ev.Exit.Process.FileEvent.FileFields.Mode), nil
	case "exit.file.modification_time":
		return int(ev.Exit.Process.FileEvent.FileFields.MTime), nil
	case "exit.file.mount_id":
		return int(ev.Exit.Process.FileEvent.FileFields.PathKey.MountID), nil
	case "exit.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent), nil
	case "exit.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.FileEvent.FileFields)), nil
	case "exit.file.uid":
		return int(ev.Exit.Process.FileEvent.FileFields.UID), nil
	case "exit.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.FileEvent.FileFields), nil
	case "exit.fsgid":
		return int(ev.Exit.Process.Credentials.FSGID), nil
	case "exit.fsgroup":
		return ev.Exit.Process.Credentials.FSGroup, nil
	case "exit.fsuid":
		return int(ev.Exit.Process.Credentials.FSUID), nil
	case "exit.fsuser":
		return ev.Exit.Process.Credentials.FSUser, nil
	case "exit.gid":
		return int(ev.Exit.Process.Credentials.GID), nil
	case "exit.group":
		return ev.Exit.Process.Credentials.Group, nil
	case "exit.interpreter.file.change_time":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime), nil
	case "exit.interpreter.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.gid":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID), nil
	case "exit.interpreter.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.interpreter.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.interpreter.file.inode":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode), nil
	case "exit.interpreter.file.mode":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode), nil
	case "exit.interpreter.file.modification_time":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime), nil
	case "exit.interpreter.file.mount_id":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID), nil
	case "exit.interpreter.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.LinuxBinprm.FileEvent), nil
	case "exit.interpreter.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields)), nil
	case "exit.interpreter.file.uid":
		return int(ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID), nil
	case "exit.interpreter.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Exit.Process.LinuxBinprm.FileEvent.FileFields), nil
	case "exit.is_kworker":
		return ev.Exit.Process.PIDContext.IsKworker, nil
	case "exit.is_thread":
		return ev.Exit.Process.IsThread, nil
	case "exit.pid":
		return int(ev.Exit.Process.PIDContext.Pid), nil
	case "exit.ppid":
		return int(ev.Exit.Process.PPid), nil
	case "exit.tid":
		return int(ev.Exit.Process.PIDContext.Tid), nil
	case "exit.tty_name":
		return ev.Exit.Process.TTYName, nil
	case "exit.uid":
		return int(ev.Exit.Process.Credentials.UID), nil
	case "exit.user":
		return ev.Exit.Process.Credentials.User, nil
	case "link.file.change_time":
		return int(ev.Link.Source.FileFields.CTime), nil
	case "link.file.destination.change_time":
		return int(ev.Link.Target.FileFields.CTime), nil
	case "link.file.destination.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Link.Target), nil
	case "link.file.destination.gid":
		return int(ev.Link.Target.FileFields.GID), nil
	case "link.file.destination.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Link.Target.FileFields), nil
	case "link.file.destination.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Link.Target.FileFields), nil
	case "link.file.destination.inode":
		return int(ev.Link.Target.FileFields.PathKey.Inode), nil
	case "link.file.destination.mode":
		return int(ev.Link.Target.FileFields.Mode), nil
	case "link.file.destination.modification_time":
		return int(ev.Link.Target.FileFields.MTime), nil
	case "link.file.destination.mount_id":
		return int(ev.Link.Target.FileFields.PathKey.MountID), nil
	case "link.file.destination.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Target), nil
	case "link.file.destination.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Target), nil
	case "link.file.destination.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Link.Target), nil
	case "link.file.destination.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Link.Target), nil
	case "link.file.destination.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Link.Target), nil
	case "link.file.destination.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Target), nil
	case "link.file.destination.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Target), nil
	case "link.file.destination.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Link.Target.FileFields)), nil
	case "link.file.destination.uid":
		return int(ev.Link.Target.FileFields.UID), nil
	case "link.file.destination.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Link.Target.FileFields), nil
	case "link.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Link.Source), nil
	case "link.file.gid":
		return int(ev.Link.Source.FileFields.GID), nil
	case "link.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Link.Source.FileFields), nil
	case "link.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Link.Source.FileFields), nil
	case "link.file.inode":
		return int(ev.Link.Source.FileFields.PathKey.Inode), nil
	case "link.file.mode":
		return int(ev.Link.Source.FileFields.Mode), nil
	case "link.file.modification_time":
		return int(ev.Link.Source.FileFields.MTime), nil
	case "link.file.mount_id":
		return int(ev.Link.Source.FileFields.PathKey.MountID), nil
	case "link.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Source), nil
	case "link.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Link.Source), nil
	case "link.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Link.Source), nil
	case "link.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Link.Source), nil
	case "link.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Link.Source), nil
	case "link.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Source), nil
	case "link.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Link.Source), nil
	case "link.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Link.Source.FileFields)), nil
	case "link.file.uid":
		return int(ev.Link.Source.FileFields.UID), nil
	case "link.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Link.Source.FileFields), nil
	case "link.retval":
		return int(ev.Link.SyscallEvent.Retval), nil
	case "load_module.args":
		return ev.FieldHandlers.ResolveModuleArgs(ev, &ev.LoadModule), nil
	case "load_module.args_truncated":
		return ev.LoadModule.ArgsTruncated, nil
	case "load_module.argv":
		return ev.FieldHandlers.ResolveModuleArgv(ev, &ev.LoadModule), nil
	case "load_module.file.change_time":
		return int(ev.LoadModule.File.FileFields.CTime), nil
	case "load_module.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.LoadModule.File), nil
	case "load_module.file.gid":
		return int(ev.LoadModule.File.FileFields.GID), nil
	case "load_module.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.LoadModule.File.FileFields), nil
	case "load_module.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.LoadModule.File.FileFields), nil
	case "load_module.file.inode":
		return int(ev.LoadModule.File.FileFields.PathKey.Inode), nil
	case "load_module.file.mode":
		return int(ev.LoadModule.File.FileFields.Mode), nil
	case "load_module.file.modification_time":
		return int(ev.LoadModule.File.FileFields.MTime), nil
	case "load_module.file.mount_id":
		return int(ev.LoadModule.File.FileFields.PathKey.MountID), nil
	case "load_module.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.LoadModule.File), nil
	case "load_module.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.LoadModule.File), nil
	case "load_module.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.LoadModule.File), nil
	case "load_module.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.LoadModule.File), nil
	case "load_module.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.LoadModule.File), nil
	case "load_module.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.LoadModule.File), nil
	case "load_module.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.LoadModule.File), nil
	case "load_module.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.LoadModule.File.FileFields)), nil
	case "load_module.file.uid":
		return int(ev.LoadModule.File.FileFields.UID), nil
	case "load_module.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.LoadModule.File.FileFields), nil
	case "load_module.loaded_from_memory":
		return ev.LoadModule.LoadedFromMemory, nil
	case "load_module.name":
		return ev.LoadModule.Name, nil
	case "load_module.retval":
		return int(ev.LoadModule.SyscallEvent.Retval), nil
	case "mkdir.file.change_time":
		return int(ev.Mkdir.File.FileFields.CTime), nil
	case "mkdir.file.destination.mode":
		return int(ev.Mkdir.Mode), nil
	case "mkdir.file.destination.rights":
		return int(ev.Mkdir.Mode), nil
	case "mkdir.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Mkdir.File), nil
	case "mkdir.file.gid":
		return int(ev.Mkdir.File.FileFields.GID), nil
	case "mkdir.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Mkdir.File.FileFields), nil
	case "mkdir.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Mkdir.File.FileFields), nil
	case "mkdir.file.inode":
		return int(ev.Mkdir.File.FileFields.PathKey.Inode), nil
	case "mkdir.file.mode":
		return int(ev.Mkdir.File.FileFields.Mode), nil
	case "mkdir.file.modification_time":
		return int(ev.Mkdir.File.FileFields.MTime), nil
	case "mkdir.file.mount_id":
		return int(ev.Mkdir.File.FileFields.PathKey.MountID), nil
	case "mkdir.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Mkdir.File), nil
	case "mkdir.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Mkdir.File), nil
	case "mkdir.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Mkdir.File), nil
	case "mkdir.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Mkdir.File), nil
	case "mkdir.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Mkdir.File), nil
	case "mkdir.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Mkdir.File), nil
	case "mkdir.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Mkdir.File), nil
	case "mkdir.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Mkdir.File.FileFields)), nil
	case "mkdir.file.uid":
		return int(ev.Mkdir.File.FileFields.UID), nil
	case "mkdir.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Mkdir.File.FileFields), nil
	case "mkdir.retval":
		return int(ev.Mkdir.SyscallEvent.Retval), nil
	case "mmap.file.change_time":
		return int(ev.MMap.File.FileFields.CTime), nil
	case "mmap.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.MMap.File), nil
	case "mmap.file.gid":
		return int(ev.MMap.File.FileFields.GID), nil
	case "mmap.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.MMap.File.FileFields), nil
	case "mmap.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.MMap.File.FileFields), nil
	case "mmap.file.inode":
		return int(ev.MMap.File.FileFields.PathKey.Inode), nil
	case "mmap.file.mode":
		return int(ev.MMap.File.FileFields.Mode), nil
	case "mmap.file.modification_time":
		return int(ev.MMap.File.FileFields.MTime), nil
	case "mmap.file.mount_id":
		return int(ev.MMap.File.FileFields.PathKey.MountID), nil
	case "mmap.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.MMap.File), nil
	case "mmap.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.MMap.File), nil
	case "mmap.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.MMap.File), nil
	case "mmap.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.MMap.File), nil
	case "mmap.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.MMap.File), nil
	case "mmap.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.MMap.File), nil
	case "mmap.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.MMap.File), nil
	case "mmap.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.MMap.File.FileFields)), nil
	case "mmap.file.uid":
		return int(ev.MMap.File.FileFields.UID), nil
	case "mmap.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.MMap.File.FileFields), nil
	case "mmap.flags":
		return ev.MMap.Flags, nil
	case "mmap.protection":
		return ev.MMap.Protection, nil
	case "mmap.retval":
		return int(ev.MMap.SyscallEvent.Retval), nil
	case "mount.fs_type":
		return ev.Mount.Mount.FSType, nil
	case "mount.mountpoint.path":
		return ev.FieldHandlers.ResolveMountPointPath(ev, &ev.Mount), nil
	case "mount.retval":
		return int(ev.Mount.SyscallEvent.Retval), nil
	case "mount.source.path":
		return ev.FieldHandlers.ResolveMountSourcePath(ev, &ev.Mount), nil
	case "mprotect.req_protection":
		return ev.MProtect.ReqProtection, nil
	case "mprotect.retval":
		return int(ev.MProtect.SyscallEvent.Retval), nil
	case "mprotect.vm_protection":
		return ev.MProtect.VMProtection, nil
	case "open.file.change_time":
		return int(ev.Open.File.FileFields.CTime), nil
	case "open.file.destination.mode":
		return int(ev.Open.Mode), nil
	case "open.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Open.File), nil
	case "open.file.gid":
		return int(ev.Open.File.FileFields.GID), nil
	case "open.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Open.File.FileFields), nil
	case "open.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Open.File.FileFields), nil
	case "open.file.inode":
		return int(ev.Open.File.FileFields.PathKey.Inode), nil
	case "open.file.mode":
		return int(ev.Open.File.FileFields.Mode), nil
	case "open.file.modification_time":
		return int(ev.Open.File.FileFields.MTime), nil
	case "open.file.mount_id":
		return int(ev.Open.File.FileFields.PathKey.MountID), nil
	case "open.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Open.File), nil
	case "open.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Open.File), nil
	case "open.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Open.File), nil
	case "open.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Open.File), nil
	case "open.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Open.File), nil
	case "open.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Open.File), nil
	case "open.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Open.File), nil
	case "open.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Open.File.FileFields)), nil
	case "open.file.uid":
		return int(ev.Open.File.FileFields.UID), nil
	case "open.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Open.File.FileFields), nil
	case "open.flags":
		return int(ev.Open.Flags), nil
	case "open.retval":
		return int(ev.Open.SyscallEvent.Retval), nil
	case "ptrace.request":
		return int(ev.PTrace.Request), nil
	case "ptrace.retval":
		return int(ev.PTrace.SyscallEvent.Retval), nil
	case "removexattr.file.change_time":
		return int(ev.RemoveXAttr.File.FileFields.CTime), nil
	case "removexattr.file.destination.name":
		return ev.FieldHandlers.ResolveXAttrName(ev, &ev.RemoveXAttr), nil
	case "removexattr.file.destination.namespace":
		return ev.FieldHandlers.ResolveXAttrNamespace(ev, &ev.RemoveXAttr), nil
	case "removexattr.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.gid":
		return int(ev.RemoveXAttr.File.FileFields.GID), nil
	case "removexattr.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.RemoveXAttr.File.FileFields), nil
	case "removexattr.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.RemoveXAttr.File.FileFields), nil
	case "removexattr.file.inode":
		return int(ev.RemoveXAttr.File.FileFields.PathKey.Inode), nil
	case "removexattr.file.mode":
		return int(ev.RemoveXAttr.File.FileFields.Mode), nil
	case "removexattr.file.modification_time":
		return int(ev.RemoveXAttr.File.FileFields.MTime), nil
	case "removexattr.file.mount_id":
		return int(ev.RemoveXAttr.File.FileFields.PathKey.MountID), nil
	case "removexattr.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.RemoveXAttr.File), nil
	case "removexattr.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.RemoveXAttr.File.FileFields)), nil
	case "removexattr.file.uid":
		return int(ev.RemoveXAttr.File.FileFields.UID), nil
	case "removexattr.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.RemoveXAttr.File.FileFields), nil
	case "removexattr.retval":
		return int(ev.RemoveXAttr.SyscallEvent.Retval), nil
	case "rename.file.change_time":
		return int(ev.Rename.Old.FileFields.CTime), nil
	case "rename.file.destination.change_time":
		return int(ev.Rename.New.FileFields.CTime), nil
	case "rename.file.destination.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rename.New), nil
	case "rename.file.destination.gid":
		return int(ev.Rename.New.FileFields.GID), nil
	case "rename.file.destination.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rename.New.FileFields), nil
	case "rename.file.destination.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rename.New.FileFields), nil
	case "rename.file.destination.inode":
		return int(ev.Rename.New.FileFields.PathKey.Inode), nil
	case "rename.file.destination.mode":
		return int(ev.Rename.New.FileFields.Mode), nil
	case "rename.file.destination.modification_time":
		return int(ev.Rename.New.FileFields.MTime), nil
	case "rename.file.destination.mount_id":
		return int(ev.Rename.New.FileFields.PathKey.MountID), nil
	case "rename.file.destination.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.New), nil
	case "rename.file.destination.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.New), nil
	case "rename.file.destination.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rename.New), nil
	case "rename.file.destination.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rename.New), nil
	case "rename.file.destination.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rename.New), nil
	case "rename.file.destination.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.New), nil
	case "rename.file.destination.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.New), nil
	case "rename.file.destination.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rename.New.FileFields)), nil
	case "rename.file.destination.uid":
		return int(ev.Rename.New.FileFields.UID), nil
	case "rename.file.destination.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rename.New.FileFields), nil
	case "rename.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rename.Old), nil
	case "rename.file.gid":
		return int(ev.Rename.Old.FileFields.GID), nil
	case "rename.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rename.Old.FileFields), nil
	case "rename.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rename.Old.FileFields), nil
	case "rename.file.inode":
		return int(ev.Rename.Old.FileFields.PathKey.Inode), nil
	case "rename.file.mode":
		return int(ev.Rename.Old.FileFields.Mode), nil
	case "rename.file.modification_time":
		return int(ev.Rename.Old.FileFields.MTime), nil
	case "rename.file.mount_id":
		return int(ev.Rename.Old.FileFields.PathKey.MountID), nil
	case "rename.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.Old), nil
	case "rename.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rename.Old), nil
	case "rename.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rename.Old), nil
	case "rename.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rename.Old), nil
	case "rename.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rename.Old), nil
	case "rename.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.Old), nil
	case "rename.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rename.Old), nil
	case "rename.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rename.Old.FileFields)), nil
	case "rename.file.uid":
		return int(ev.Rename.Old.FileFields.UID), nil
	case "rename.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rename.Old.FileFields), nil
	case "rename.retval":
		return int(ev.Rename.SyscallEvent.Retval), nil
	case "rmdir.file.change_time":
		return int(ev.Rmdir.File.FileFields.CTime), nil
	case "rmdir.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Rmdir.File), nil
	case "rmdir.file.gid":
		return int(ev.Rmdir.File.FileFields.GID), nil
	case "rmdir.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Rmdir.File.FileFields), nil
	case "rmdir.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Rmdir.File.FileFields), nil
	case "rmdir.file.inode":
		return int(ev.Rmdir.File.FileFields.PathKey.Inode), nil
	case "rmdir.file.mode":
		return int(ev.Rmdir.File.FileFields.Mode), nil
	case "rmdir.file.modification_time":
		return int(ev.Rmdir.File.FileFields.MTime), nil
	case "rmdir.file.mount_id":
		return int(ev.Rmdir.File.FileFields.PathKey.MountID), nil
	case "rmdir.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rmdir.File), nil
	case "rmdir.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Rmdir.File), nil
	case "rmdir.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Rmdir.File), nil
	case "rmdir.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Rmdir.File), nil
	case "rmdir.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Rmdir.File), nil
	case "rmdir.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rmdir.File), nil
	case "rmdir.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Rmdir.File), nil
	case "rmdir.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Rmdir.File.FileFields)), nil
	case "rmdir.file.uid":
		return int(ev.Rmdir.File.FileFields.UID), nil
	case "rmdir.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Rmdir.File.FileFields), nil
	case "rmdir.retval":
		return int(ev.Rmdir.SyscallEvent.Retval), nil
	case "selinux.bool.name":
		return ev.FieldHandlers.ResolveSELinuxBoolName(ev, &ev.SELinux), nil
	case "selinux.bool.state":
		return ev.SELinux.BoolChangeValue, nil
	case "selinux.bool_commit.state":
		return ev.SELinux.BoolCommitValue, nil
	case "selinux.enforce.status":
		return ev.SELinux.EnforceStatus, nil
	case "setgid.egid":
		return int(ev.SetGID.EGID), nil
	case "setgid.egroup":
		return ev.FieldHandlers.ResolveSetgidEGroup(ev, &ev.SetGID), nil
	case "setgid.fsgid":
		return int(ev.SetGID.FSGID), nil
	case "setgid.fsgroup":
		return ev.FieldHandlers.ResolveSetgidFSGroup(ev, &ev.SetGID), nil
	case "setgid.gid":
		return int(ev.SetGID.GID), nil
	case "setgid.group":
		return ev.FieldHandlers.ResolveSetgidGroup(ev, &ev.SetGID), nil
	case "setuid.euid":
		return int(ev.SetUID.EUID), nil
	case "setuid.euser":
		return ev.FieldHandlers.ResolveSetuidEUser(ev, &ev.SetUID), nil
	case "setuid.fsuid":
		return int(ev.SetUID.FSUID), nil
	case "setuid.fsuser":
		return ev.FieldHandlers.ResolveSetuidFSUser(ev, &ev.SetUID), nil
	case "setuid.uid":
		return int(ev.SetUID.UID), nil
	case "setuid.user":
		return ev.FieldHandlers.ResolveSetuidUser(ev, &ev.SetUID), nil
	case "setxattr.file.change_time":
		return int(ev.SetXAttr.File.FileFields.CTime), nil
	case "setxattr.file.destination.name":
		return ev.FieldHandlers.ResolveXAttrName(ev, &ev.SetXAttr), nil
	case "setxattr.file.destination.namespace":
		return ev.FieldHandlers.ResolveXAttrNamespace(ev, &ev.SetXAttr), nil
	case "setxattr.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.gid":
		return int(ev.SetXAttr.File.FileFields.GID), nil
	case "setxattr.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.SetXAttr.File.FileFields), nil
	case "setxattr.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.SetXAttr.File.FileFields), nil
	case "setxattr.file.inode":
		return int(ev.SetXAttr.File.FileFields.PathKey.Inode), nil
	case "setxattr.file.mode":
		return int(ev.SetXAttr.File.FileFields.Mode), nil
	case "setxattr.file.modification_time":
		return int(ev.SetXAttr.File.FileFields.MTime), nil
	case "setxattr.file.mount_id":
		return int(ev.SetXAttr.File.FileFields.PathKey.MountID), nil
	case "setxattr.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.SetXAttr.File), nil
	case "setxattr.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.SetXAttr.File.FileFields)), nil
	case "setxattr.file.uid":
		return int(ev.SetXAttr.File.FileFields.UID), nil
	case "setxattr.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.SetXAttr.File.FileFields), nil
	case "setxattr.retval":
		return int(ev.SetXAttr.SyscallEvent.Retval), nil
	case "signal.pid":
		return int(ev.Signal.PID), nil
	case "signal.retval":
		return int(ev.Signal.SyscallEvent.Retval), nil
	case "signal.type":
		return int(ev.Signal.Type), nil
	case "splice.file.change_time":
		return int(ev.Splice.File.FileFields.CTime), nil
	case "splice.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Splice.File), nil
	case "splice.file.gid":
		return int(ev.Splice.File.FileFields.GID), nil
	case "splice.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Splice.File.FileFields), nil
	case "splice.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Splice.File.FileFields), nil
	case "splice.file.inode":
		return int(ev.Splice.File.FileFields.PathKey.Inode), nil
	case "splice.file.mode":
		return int(ev.Splice.File.FileFields.Mode), nil
	case "splice.file.modification_time":
		return int(ev.Splice.File.FileFields.MTime), nil
	case "splice.file.mount_id":
		return int(ev.Splice.File.FileFields.PathKey.MountID), nil
	case "splice.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Splice.File), nil
	case "splice.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Splice.File), nil
	case "splice.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Splice.File), nil
	case "splice.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Splice.File), nil
	case "splice.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Splice.File), nil
	case "splice.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Splice.File), nil
	case "splice.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Splice.File), nil
	case "splice.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Splice.File.FileFields)), nil
	case "splice.file.uid":
		return int(ev.Splice.File.FileFields.UID), nil
	case "splice.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Splice.File.FileFields), nil
	case "splice.pipe_entry_flag":
		return int(ev.Splice.PipeEntryFlag), nil
	case "splice.pipe_exit_flag":
		return int(ev.Splice.PipeExitFlag), nil
	case "splice.retval":
		return int(ev.Splice.SyscallEvent.Retval), nil
	case "unlink.file.change_time":
		return int(ev.Unlink.File.FileFields.CTime), nil
	case "unlink.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Unlink.File), nil
	case "unlink.file.gid":
		return int(ev.Unlink.File.FileFields.GID), nil
	case "unlink.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Unlink.File.FileFields), nil
	case "unlink.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Unlink.File.FileFields), nil
	case "unlink.file.inode":
		return int(ev.Unlink.File.FileFields.PathKey.Inode), nil
	case "unlink.file.mode":
		return int(ev.Unlink.File.FileFields.Mode), nil
	case "unlink.file.modification_time":
		return int(ev.Unlink.File.FileFields.MTime), nil
	case "unlink.file.mount_id":
		return int(ev.Unlink.File.FileFields.PathKey.MountID), nil
	case "unlink.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Unlink.File), nil
	case "unlink.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Unlink.File), nil
	case "unlink.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Unlink.File), nil
	case "unlink.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Unlink.File), nil
	case "unlink.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Unlink.File), nil
	case "unlink.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Unlink.File), nil
	case "unlink.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Unlink.File), nil
	case "unlink.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Unlink.File.FileFields)), nil
	case "unlink.file.uid":
		return int(ev.Unlink.File.FileFields.UID), nil
	case "unlink.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Unlink.File.FileFields), nil
	case "unlink.flags":
		return int(ev.Unlink.Flags), nil
	case "unlink.retval":
		return int(ev.Unlink.SyscallEvent.Retval), nil
	case "unload_module.name":
		return ev.UnloadModule.Name, nil
	case "unload_module.retval":
		return int(ev.UnloadModule.SyscallEvent.Retval), nil
	case "utimes.file.change_time":
		return int(ev.Utimes.File.FileFields.CTime), nil
	case "utimes.file.filesystem":
		return ev.FieldHandlers.ResolveFileFilesystem(ev, &ev.Utimes.File), nil
	case "utimes.file.gid":
		return int(ev.Utimes.File.FileFields.GID), nil
	case "utimes.file.group":
		return ev.FieldHandlers.ResolveFileFieldsGroup(ev, &ev.Utimes.File.FileFields), nil
	case "utimes.file.in_upper_layer":
		return ev.FieldHandlers.ResolveFileFieldsInUpperLayer(ev, &ev.Utimes.File.FileFields), nil
	case "utimes.file.inode":
		return int(ev.Utimes.File.FileFields.PathKey.Inode), nil
	case "utimes.file.mode":
		return int(ev.Utimes.File.FileFields.Mode), nil
	case "utimes.file.modification_time":
		return int(ev.Utimes.File.FileFields.MTime), nil
	case "utimes.file.mount_id":
		return int(ev.Utimes.File.FileFields.PathKey.MountID), nil
	case "utimes.file.name":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Utimes.File), nil
	case "utimes.file.name.length":
		return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Utimes.File), nil
	case "utimes.file.package.name":
		return ev.FieldHandlers.ResolvePackageName(ev, &ev.Utimes.File), nil
	case "utimes.file.package.source_version":
		return ev.FieldHandlers.ResolvePackageSourceVersion(ev, &ev.Utimes.File), nil
	case "utimes.file.package.version":
		return ev.FieldHandlers.ResolvePackageVersion(ev, &ev.Utimes.File), nil
	case "utimes.file.path":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Utimes.File), nil
	case "utimes.file.path.length":
		return ev.FieldHandlers.ResolveFilePath(ev, &ev.Utimes.File), nil
	case "utimes.file.rights":
		return int(ev.FieldHandlers.ResolveRights(ev, &ev.Utimes.File.FileFields)), nil
	case "utimes.file.uid":
		return int(ev.Utimes.File.FileFields.UID), nil
	case "utimes.file.user":
		return ev.FieldHandlers.ResolveFileFieldsUser(ev, &ev.Utimes.File.FileFields), nil
	case "utimes.retval":
		return int(ev.Utimes.SyscallEvent.Retval), nil
	}
	return nil, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldEventType(field eval.Field) (eval.EventType, error) {
	switch field {
	case "bind.addr.family":
		return "bind", nil
	case "bind.addr.ip":
		return "bind", nil
	case "bind.addr.port":
		return "bind", nil
	case "bind.retval":
		return "bind", nil
	case "bpf.cmd":
		return "bpf", nil
	case "bpf.map.name":
		return "bpf", nil
	case "bpf.map.type":
		return "bpf", nil
	case "bpf.prog.attach_type":
		return "bpf", nil
	case "bpf.prog.helpers":
		return "bpf", nil
	case "bpf.prog.name":
		return "bpf", nil
	case "bpf.prog.tag":
		return "bpf", nil
	case "bpf.prog.type":
		return "bpf", nil
	case "bpf.retval":
		return "bpf", nil
	case "capset.cap_effective":
		return "capset", nil
	case "capset.cap_permitted":
		return "capset", nil
	case "chmod.file.change_time":
		return "chmod", nil
	case "chmod.file.destination.mode":
		return "chmod", nil
	case "chmod.file.destination.rights":
		return "chmod", nil
	case "chmod.file.filesystem":
		return "chmod", nil
	case "chmod.file.gid":
		return "chmod", nil
	case "chmod.file.group":
		return "chmod", nil
	case "chmod.file.in_upper_layer":
		return "chmod", nil
	case "chmod.file.inode":
		return "chmod", nil
	case "chmod.file.mode":
		return "chmod", nil
	case "chmod.file.modification_time":
		return "chmod", nil
	case "chmod.file.mount_id":
		return "chmod", nil
	case "chmod.file.name":
		return "chmod", nil
	case "chmod.file.name.length":
		return "chmod", nil
	case "chmod.file.package.name":
		return "chmod", nil
	case "chmod.file.package.source_version":
		return "chmod", nil
	case "chmod.file.package.version":
		return "chmod", nil
	case "chmod.file.path":
		return "chmod", nil
	case "chmod.file.path.length":
		return "chmod", nil
	case "chmod.file.rights":
		return "chmod", nil
	case "chmod.file.uid":
		return "chmod", nil
	case "chmod.file.user":
		return "chmod", nil
	case "chmod.retval":
		return "chmod", nil
	case "chown.file.change_time":
		return "chown", nil
	case "chown.file.destination.gid":
		return "chown", nil
	case "chown.file.destination.group":
		return "chown", nil
	case "chown.file.destination.uid":
		return "chown", nil
	case "chown.file.destination.user":
		return "chown", nil
	case "chown.file.filesystem":
		return "chown", nil
	case "chown.file.gid":
		return "chown", nil
	case "chown.file.group":
		return "chown", nil
	case "chown.file.in_upper_layer":
		return "chown", nil
	case "chown.file.inode":
		return "chown", nil
	case "chown.file.mode":
		return "chown", nil
	case "chown.file.modification_time":
		return "chown", nil
	case "chown.file.mount_id":
		return "chown", nil
	case "chown.file.name":
		return "chown", nil
	case "chown.file.name.length":
		return "chown", nil
	case "chown.file.package.name":
		return "chown", nil
	case "chown.file.package.source_version":
		return "chown", nil
	case "chown.file.package.version":
		return "chown", nil
	case "chown.file.path":
		return "chown", nil
	case "chown.file.path.length":
		return "chown", nil
	case "chown.file.rights":
		return "chown", nil
	case "chown.file.uid":
		return "chown", nil
	case "chown.file.user":
		return "chown", nil
	case "chown.retval":
		return "chown", nil
	case "dns.id":
		return "dns", nil
	case "dns.question.class":
		return "dns", nil
	case "dns.question.count":
		return "dns", nil
	case "dns.question.length":
		return "dns", nil
	case "dns.question.name":
		return "dns", nil
	case "dns.question.name.length":
		return "dns", nil
	case "dns.question.type":
		return "dns", nil
	case "event.async":
		return "*", nil
	case "exec.args":
		return "exec", nil
	case "exec.args_flags":
		return "exec", nil
	case "exec.args_options":
		return "exec", nil
	case "exec.args_truncated":
		return "exec", nil
	case "exec.argv":
		return "exec", nil
	case "exec.argv0":
		return "exec", nil
	case "exec.cap_effective":
		return "exec", nil
	case "exec.cap_permitted":
		return "exec", nil
	case "exec.comm":
		return "exec", nil
	case "exec.container.id":
		return "exec", nil
	case "exec.created_at":
		return "exec", nil
	case "exec.egid":
		return "exec", nil
	case "exec.egroup":
		return "exec", nil
	case "exec.envp":
		return "exec", nil
	case "exec.envs":
		return "exec", nil
	case "exec.envs_truncated":
		return "exec", nil
	case "exec.euid":
		return "exec", nil
	case "exec.euser":
		return "exec", nil
	case "exec.file.change_time":
		return "exec", nil
	case "exec.file.filesystem":
		return "exec", nil
	case "exec.file.gid":
		return "exec", nil
	case "exec.file.group":
		return "exec", nil
	case "exec.file.in_upper_layer":
		return "exec", nil
	case "exec.file.inode":
		return "exec", nil
	case "exec.file.mode":
		return "exec", nil
	case "exec.file.modification_time":
		return "exec", nil
	case "exec.file.mount_id":
		return "exec", nil
	case "exec.file.name":
		return "exec", nil
	case "exec.file.name.length":
		return "exec", nil
	case "exec.file.package.name":
		return "exec", nil
	case "exec.file.package.source_version":
		return "exec", nil
	case "exec.file.package.version":
		return "exec", nil
	case "exec.file.path":
		return "exec", nil
	case "exec.file.path.length":
		return "exec", nil
	case "exec.file.rights":
		return "exec", nil
	case "exec.file.uid":
		return "exec", nil
	case "exec.file.user":
		return "exec", nil
	case "exec.fsgid":
		return "exec", nil
	case "exec.fsgroup":
		return "exec", nil
	case "exec.fsuid":
		return "exec", nil
	case "exec.fsuser":
		return "exec", nil
	case "exec.gid":
		return "exec", nil
	case "exec.group":
		return "exec", nil
	case "exec.interpreter.file.change_time":
		return "exec", nil
	case "exec.interpreter.file.filesystem":
		return "exec", nil
	case "exec.interpreter.file.gid":
		return "exec", nil
	case "exec.interpreter.file.group":
		return "exec", nil
	case "exec.interpreter.file.in_upper_layer":
		return "exec", nil
	case "exec.interpreter.file.inode":
		return "exec", nil
	case "exec.interpreter.file.mode":
		return "exec", nil
	case "exec.interpreter.file.modification_time":
		return "exec", nil
	case "exec.interpreter.file.mount_id":
		return "exec", nil
	case "exec.interpreter.file.name":
		return "exec", nil
	case "exec.interpreter.file.name.length":
		return "exec", nil
	case "exec.interpreter.file.package.name":
		return "exec", nil
	case "exec.interpreter.file.package.source_version":
		return "exec", nil
	case "exec.interpreter.file.package.version":
		return "exec", nil
	case "exec.interpreter.file.path":
		return "exec", nil
	case "exec.interpreter.file.path.length":
		return "exec", nil
	case "exec.interpreter.file.rights":
		return "exec", nil
	case "exec.interpreter.file.uid":
		return "exec", nil
	case "exec.interpreter.file.user":
		return "exec", nil
	case "exec.is_kworker":
		return "exec", nil
	case "exec.is_thread":
		return "exec", nil
	case "exec.pid":
		return "exec", nil
	case "exec.ppid":
		return "exec", nil
	case "exec.tid":
		return "exec", nil
	case "exec.tty_name":
		return "exec", nil
	case "exec.uid":
		return "exec", nil
	case "exec.user":
		return "exec", nil
	case "exit.args":
		return "exit", nil
	case "exit.args_flags":
		return "exit", nil
	case "exit.args_options":
		return "exit", nil
	case "exit.args_truncated":
		return "exit", nil
	case "exit.argv":
		return "exit", nil
	case "exit.argv0":
		return "exit", nil
	case "exit.cap_effective":
		return "exit", nil
	case "exit.cap_permitted":
		return "exit", nil
	case "exit.cause":
		return "exit", nil
	case "exit.code":
		return "exit", nil
	case "exit.comm":
		return "exit", nil
	case "exit.container.id":
		return "exit", nil
	case "exit.created_at":
		return "exit", nil
	case "exit.egid":
		return "exit", nil
	case "exit.egroup":
		return "exit", nil
	case "exit.envp":
		return "exit", nil
	case "exit.envs":
		return "exit", nil
	case "exit.envs_truncated":
		return "exit", nil
	case "exit.euid":
		return "exit", nil
	case "exit.euser":
		return "exit", nil
	case "exit.file.change_time":
		return "exit", nil
	case "exit.file.filesystem":
		return "exit", nil
	case "exit.file.gid":
		return "exit", nil
	case "exit.file.group":
		return "exit", nil
	case "exit.file.in_upper_layer":
		return "exit", nil
	case "exit.file.inode":
		return "exit", nil
	case "exit.file.mode":
		return "exit", nil
	case "exit.file.modification_time":
		return "exit", nil
	case "exit.file.mount_id":
		return "exit", nil
	case "exit.file.name":
		return "exit", nil
	case "exit.file.name.length":
		return "exit", nil
	case "exit.file.package.name":
		return "exit", nil
	case "exit.file.package.source_version":
		return "exit", nil
	case "exit.file.package.version":
		return "exit", nil
	case "exit.file.path":
		return "exit", nil
	case "exit.file.path.length":
		return "exit", nil
	case "exit.file.rights":
		return "exit", nil
	case "exit.file.uid":
		return "exit", nil
	case "exit.file.user":
		return "exit", nil
	case "exit.fsgid":
		return "exit", nil
	case "exit.fsgroup":
		return "exit", nil
	case "exit.fsuid":
		return "exit", nil
	case "exit.fsuser":
		return "exit", nil
	case "exit.gid":
		return "exit", nil
	case "exit.group":
		return "exit", nil
	case "exit.interpreter.file.change_time":
		return "exit", nil
	case "exit.interpreter.file.filesystem":
		return "exit", nil
	case "exit.interpreter.file.gid":
		return "exit", nil
	case "exit.interpreter.file.group":
		return "exit", nil
	case "exit.interpreter.file.in_upper_layer":
		return "exit", nil
	case "exit.interpreter.file.inode":
		return "exit", nil
	case "exit.interpreter.file.mode":
		return "exit", nil
	case "exit.interpreter.file.modification_time":
		return "exit", nil
	case "exit.interpreter.file.mount_id":
		return "exit", nil
	case "exit.interpreter.file.name":
		return "exit", nil
	case "exit.interpreter.file.name.length":
		return "exit", nil
	case "exit.interpreter.file.package.name":
		return "exit", nil
	case "exit.interpreter.file.package.source_version":
		return "exit", nil
	case "exit.interpreter.file.package.version":
		return "exit", nil
	case "exit.interpreter.file.path":
		return "exit", nil
	case "exit.interpreter.file.path.length":
		return "exit", nil
	case "exit.interpreter.file.rights":
		return "exit", nil
	case "exit.interpreter.file.uid":
		return "exit", nil
	case "exit.interpreter.file.user":
		return "exit", nil
	case "exit.is_kworker":
		return "exit", nil
	case "exit.is_thread":
		return "exit", nil
	case "exit.pid":
		return "exit", nil
	case "exit.ppid":
		return "exit", nil
	case "exit.tid":
		return "exit", nil
	case "exit.tty_name":
		return "exit", nil
	case "exit.uid":
		return "exit", nil
	case "exit.user":
		return "exit", nil
	case "link.file.change_time":
		return "link", nil
	case "link.file.destination.change_time":
		return "link", nil
	case "link.file.destination.filesystem":
		return "link", nil
	case "link.file.destination.gid":
		return "link", nil
	case "link.file.destination.group":
		return "link", nil
	case "link.file.destination.in_upper_layer":
		return "link", nil
	case "link.file.destination.inode":
		return "link", nil
	case "link.file.destination.mode":
		return "link", nil
	case "link.file.destination.modification_time":
		return "link", nil
	case "link.file.destination.mount_id":
		return "link", nil
	case "link.file.destination.name":
		return "link", nil
	case "link.file.destination.name.length":
		return "link", nil
	case "link.file.destination.package.name":
		return "link", nil
	case "link.file.destination.package.source_version":
		return "link", nil
	case "link.file.destination.package.version":
		return "link", nil
	case "link.file.destination.path":
		return "link", nil
	case "link.file.destination.path.length":
		return "link", nil
	case "link.file.destination.rights":
		return "link", nil
	case "link.file.destination.uid":
		return "link", nil
	case "link.file.destination.user":
		return "link", nil
	case "link.file.filesystem":
		return "link", nil
	case "link.file.gid":
		return "link", nil
	case "link.file.group":
		return "link", nil
	case "link.file.in_upper_layer":
		return "link", nil
	case "link.file.inode":
		return "link", nil
	case "link.file.mode":
		return "link", nil
	case "link.file.modification_time":
		return "link", nil
	case "link.file.mount_id":
		return "link", nil
	case "link.file.name":
		return "link", nil
	case "link.file.name.length":
		return "link", nil
	case "link.file.package.name":
		return "link", nil
	case "link.file.package.source_version":
		return "link", nil
	case "link.file.package.version":
		return "link", nil
	case "link.file.path":
		return "link", nil
	case "link.file.path.length":
		return "link", nil
	case "link.file.rights":
		return "link", nil
	case "link.file.uid":
		return "link", nil
	case "link.file.user":
		return "link", nil
	case "link.retval":
		return "link", nil
	case "load_module.args":
		return "load_module", nil
	case "load_module.args_truncated":
		return "load_module", nil
	case "load_module.argv":
		return "load_module", nil
	case "load_module.file.change_time":
		return "load_module", nil
	case "load_module.file.filesystem":
		return "load_module", nil
	case "load_module.file.gid":
		return "load_module", nil
	case "load_module.file.group":
		return "load_module", nil
	case "load_module.file.in_upper_layer":
		return "load_module", nil
	case "load_module.file.inode":
		return "load_module", nil
	case "load_module.file.mode":
		return "load_module", nil
	case "load_module.file.modification_time":
		return "load_module", nil
	case "load_module.file.mount_id":
		return "load_module", nil
	case "load_module.file.name":
		return "load_module", nil
	case "load_module.file.name.length":
		return "load_module", nil
	case "load_module.file.package.name":
		return "load_module", nil
	case "load_module.file.package.source_version":
		return "load_module", nil
	case "load_module.file.package.version":
		return "load_module", nil
	case "load_module.file.path":
		return "load_module", nil
	case "load_module.file.path.length":
		return "load_module", nil
	case "load_module.file.rights":
		return "load_module", nil
	case "load_module.file.uid":
		return "load_module", nil
	case "load_module.file.user":
		return "load_module", nil
	case "load_module.loaded_from_memory":
		return "load_module", nil
	case "load_module.name":
		return "load_module", nil
	case "load_module.retval":
		return "load_module", nil
	case "mkdir.file.change_time":
		return "mkdir", nil
	case "mkdir.file.destination.mode":
		return "mkdir", nil
	case "mkdir.file.destination.rights":
		return "mkdir", nil
	case "mkdir.file.filesystem":
		return "mkdir", nil
	case "mkdir.file.gid":
		return "mkdir", nil
	case "mkdir.file.group":
		return "mkdir", nil
	case "mkdir.file.in_upper_layer":
		return "mkdir", nil
	case "mkdir.file.inode":
		return "mkdir", nil
	case "mkdir.file.mode":
		return "mkdir", nil
	case "mkdir.file.modification_time":
		return "mkdir", nil
	case "mkdir.file.mount_id":
		return "mkdir", nil
	case "mkdir.file.name":
		return "mkdir", nil
	case "mkdir.file.name.length":
		return "mkdir", nil
	case "mkdir.file.package.name":
		return "mkdir", nil
	case "mkdir.file.package.source_version":
		return "mkdir", nil
	case "mkdir.file.package.version":
		return "mkdir", nil
	case "mkdir.file.path":
		return "mkdir", nil
	case "mkdir.file.path.length":
		return "mkdir", nil
	case "mkdir.file.rights":
		return "mkdir", nil
	case "mkdir.file.uid":
		return "mkdir", nil
	case "mkdir.file.user":
		return "mkdir", nil
	case "mkdir.retval":
		return "mkdir", nil
	case "mmap.file.change_time":
		return "mmap", nil
	case "mmap.file.filesystem":
		return "mmap", nil
	case "mmap.file.gid":
		return "mmap", nil
	case "mmap.file.group":
		return "mmap", nil
	case "mmap.file.in_upper_layer":
		return "mmap", nil
	case "mmap.file.inode":
		return "mmap", nil
	case "mmap.file.mode":
		return "mmap", nil
	case "mmap.file.modification_time":
		return "mmap", nil
	case "mmap.file.mount_id":
		return "mmap", nil
	case "mmap.file.name":
		return "mmap", nil
	case "mmap.file.name.length":
		return "mmap", nil
	case "mmap.file.package.name":
		return "mmap", nil
	case "mmap.file.package.source_version":
		return "mmap", nil
	case "mmap.file.package.version":
		return "mmap", nil
	case "mmap.file.path":
		return "mmap", nil
	case "mmap.file.path.length":
		return "mmap", nil
	case "mmap.file.rights":
		return "mmap", nil
	case "mmap.file.uid":
		return "mmap", nil
	case "mmap.file.user":
		return "mmap", nil
	case "mmap.flags":
		return "mmap", nil
	case "mmap.protection":
		return "mmap", nil
	case "mmap.retval":
		return "mmap", nil
	case "mount.fs_type":
		return "mount", nil
	case "mount.mountpoint.path":
		return "mount", nil
	case "mount.retval":
		return "mount", nil
	case "mount.source.path":
		return "mount", nil
	case "mprotect.req_protection":
		return "mprotect", nil
	case "mprotect.retval":
		return "mprotect", nil
	case "mprotect.vm_protection":
		return "mprotect", nil
	case "open.file.change_time":
		return "open", nil
	case "open.file.destination.mode":
		return "open", nil
	case "open.file.filesystem":
		return "open", nil
	case "open.file.gid":
		return "open", nil
	case "open.file.group":
		return "open", nil
	case "open.file.in_upper_layer":
		return "open", nil
	case "open.file.inode":
		return "open", nil
	case "open.file.mode":
		return "open", nil
	case "open.file.modification_time":
		return "open", nil
	case "open.file.mount_id":
		return "open", nil
	case "open.file.name":
		return "open", nil
	case "open.file.name.length":
		return "open", nil
	case "open.file.package.name":
		return "open", nil
	case "open.file.package.source_version":
		return "open", nil
	case "open.file.package.version":
		return "open", nil
	case "open.file.path":
		return "open", nil
	case "open.file.path.length":
		return "open", nil
	case "open.file.rights":
		return "open", nil
	case "open.file.uid":
		return "open", nil
	case "open.file.user":
		return "open", nil
	case "open.flags":
		return "open", nil
	case "open.retval":
		return "open", nil
	case "ptrace.request":
		return "ptrace", nil
	case "ptrace.retval":
		return "ptrace", nil
	case "removexattr.file.change_time":
		return "removexattr", nil
	case "removexattr.file.destination.name":
		return "removexattr", nil
	case "removexattr.file.destination.namespace":
		return "removexattr", nil
	case "removexattr.file.filesystem":
		return "removexattr", nil
	case "removexattr.file.gid":
		return "removexattr", nil
	case "removexattr.file.group":
		return "removexattr", nil
	case "removexattr.file.in_upper_layer":
		return "removexattr", nil
	case "removexattr.file.inode":
		return "removexattr", nil
	case "removexattr.file.mode":
		return "removexattr", nil
	case "removexattr.file.modification_time":
		return "removexattr", nil
	case "removexattr.file.mount_id":
		return "removexattr", nil
	case "removexattr.file.name":
		return "removexattr", nil
	case "removexattr.file.name.length":
		return "removexattr", nil
	case "removexattr.file.package.name":
		return "removexattr", nil
	case "removexattr.file.package.source_version":
		return "removexattr", nil
	case "removexattr.file.package.version":
		return "removexattr", nil
	case "removexattr.file.path":
		return "removexattr", nil
	case "removexattr.file.path.length":
		return "removexattr", nil
	case "removexattr.file.rights":
		return "removexattr", nil
	case "removexattr.file.uid":
		return "removexattr", nil
	case "removexattr.file.user":
		return "removexattr", nil
	case "removexattr.retval":
		return "removexattr", nil
	case "rename.file.change_time":
		return "rename", nil
	case "rename.file.destination.change_time":
		return "rename", nil
	case "rename.file.destination.filesystem":
		return "rename", nil
	case "rename.file.destination.gid":
		return "rename", nil
	case "rename.file.destination.group":
		return "rename", nil
	case "rename.file.destination.in_upper_layer":
		return "rename", nil
	case "rename.file.destination.inode":
		return "rename", nil
	case "rename.file.destination.mode":
		return "rename", nil
	case "rename.file.destination.modification_time":
		return "rename", nil
	case "rename.file.destination.mount_id":
		return "rename", nil
	case "rename.file.destination.name":
		return "rename", nil
	case "rename.file.destination.name.length":
		return "rename", nil
	case "rename.file.destination.package.name":
		return "rename", nil
	case "rename.file.destination.package.source_version":
		return "rename", nil
	case "rename.file.destination.package.version":
		return "rename", nil
	case "rename.file.destination.path":
		return "rename", nil
	case "rename.file.destination.path.length":
		return "rename", nil
	case "rename.file.destination.rights":
		return "rename", nil
	case "rename.file.destination.uid":
		return "rename", nil
	case "rename.file.destination.user":
		return "rename", nil
	case "rename.file.filesystem":
		return "rename", nil
	case "rename.file.gid":
		return "rename", nil
	case "rename.file.group":
		return "rename", nil
	case "rename.file.in_upper_layer":
		return "rename", nil
	case "rename.file.inode":
		return "rename", nil
	case "rename.file.mode":
		return "rename", nil
	case "rename.file.modification_time":
		return "rename", nil
	case "rename.file.mount_id":
		return "rename", nil
	case "rename.file.name":
		return "rename", nil
	case "rename.file.name.length":
		return "rename", nil
	case "rename.file.package.name":
		return "rename", nil
	case "rename.file.package.source_version":
		return "rename", nil
	case "rename.file.package.version":
		return "rename", nil
	case "rename.file.path":
		return "rename", nil
	case "rename.file.path.length":
		return "rename", nil
	case "rename.file.rights":
		return "rename", nil
	case "rename.file.uid":
		return "rename", nil
	case "rename.file.user":
		return "rename", nil
	case "rename.retval":
		return "rename", nil
	case "rmdir.file.change_time":
		return "rmdir", nil
	case "rmdir.file.filesystem":
		return "rmdir", nil
	case "rmdir.file.gid":
		return "rmdir", nil
	case "rmdir.file.group":
		return "rmdir", nil
	case "rmdir.file.in_upper_layer":
		return "rmdir", nil
	case "rmdir.file.inode":
		return "rmdir", nil
	case "rmdir.file.mode":
		return "rmdir", nil
	case "rmdir.file.modification_time":
		return "rmdir", nil
	case "rmdir.file.mount_id":
		return "rmdir", nil
	case "rmdir.file.name":
		return "rmdir", nil
	case "rmdir.file.name.length":
		return "rmdir", nil
	case "rmdir.file.package.name":
		return "rmdir", nil
	case "rmdir.file.package.source_version":
		return "rmdir", nil
	case "rmdir.file.package.version":
		return "rmdir", nil
	case "rmdir.file.path":
		return "rmdir", nil
	case "rmdir.file.path.length":
		return "rmdir", nil
	case "rmdir.file.rights":
		return "rmdir", nil
	case "rmdir.file.uid":
		return "rmdir", nil
	case "rmdir.file.user":
		return "rmdir", nil
	case "rmdir.retval":
		return "rmdir", nil
	case "selinux.bool.name":
		return "selinux", nil
	case "selinux.bool.state":
		return "selinux", nil
	case "selinux.bool_commit.state":
		return "selinux", nil
	case "selinux.enforce.status":
		return "selinux", nil
	case "setgid.egid":
		return "setgid", nil
	case "setgid.egroup":
		return "setgid", nil
	case "setgid.fsgid":
		return "setgid", nil
	case "setgid.fsgroup":
		return "setgid", nil
	case "setgid.gid":
		return "setgid", nil
	case "setgid.group":
		return "setgid", nil
	case "setuid.euid":
		return "setuid", nil
	case "setuid.euser":
		return "setuid", nil
	case "setuid.fsuid":
		return "setuid", nil
	case "setuid.fsuser":
		return "setuid", nil
	case "setuid.uid":
		return "setuid", nil
	case "setuid.user":
		return "setuid", nil
	case "setxattr.file.change_time":
		return "setxattr", nil
	case "setxattr.file.destination.name":
		return "setxattr", nil
	case "setxattr.file.destination.namespace":
		return "setxattr", nil
	case "setxattr.file.filesystem":
		return "setxattr", nil
	case "setxattr.file.gid":
		return "setxattr", nil
	case "setxattr.file.group":
		return "setxattr", nil
	case "setxattr.file.in_upper_layer":
		return "setxattr", nil
	case "setxattr.file.inode":
		return "setxattr", nil
	case "setxattr.file.mode":
		return "setxattr", nil
	case "setxattr.file.modification_time":
		return "setxattr", nil
	case "setxattr.file.mount_id":
		return "setxattr", nil
	case "setxattr.file.name":
		return "setxattr", nil
	case "setxattr.file.name.length":
		return "setxattr", nil
	case "setxattr.file.package.name":
		return "setxattr", nil
	case "setxattr.file.package.source_version":
		return "setxattr", nil
	case "setxattr.file.package.version":
		return "setxattr", nil
	case "setxattr.file.path":
		return "setxattr", nil
	case "setxattr.file.path.length":
		return "setxattr", nil
	case "setxattr.file.rights":
		return "setxattr", nil
	case "setxattr.file.uid":
		return "setxattr", nil
	case "setxattr.file.user":
		return "setxattr", nil
	case "setxattr.retval":
		return "setxattr", nil
	case "signal.pid":
		return "signal", nil
	case "signal.retval":
		return "signal", nil
	case "signal.type":
		return "signal", nil
	case "splice.file.change_time":
		return "splice", nil
	case "splice.file.filesystem":
		return "splice", nil
	case "splice.file.gid":
		return "splice", nil
	case "splice.file.group":
		return "splice", nil
	case "splice.file.in_upper_layer":
		return "splice", nil
	case "splice.file.inode":
		return "splice", nil
	case "splice.file.mode":
		return "splice", nil
	case "splice.file.modification_time":
		return "splice", nil
	case "splice.file.mount_id":
		return "splice", nil
	case "splice.file.name":
		return "splice", nil
	case "splice.file.name.length":
		return "splice", nil
	case "splice.file.package.name":
		return "splice", nil
	case "splice.file.package.source_version":
		return "splice", nil
	case "splice.file.package.version":
		return "splice", nil
	case "splice.file.path":
		return "splice", nil
	case "splice.file.path.length":
		return "splice", nil
	case "splice.file.rights":
		return "splice", nil
	case "splice.file.uid":
		return "splice", nil
	case "splice.file.user":
		return "splice", nil
	case "splice.pipe_entry_flag":
		return "splice", nil
	case "splice.pipe_exit_flag":
		return "splice", nil
	case "splice.retval":
		return "splice", nil
	case "unlink.file.change_time":
		return "unlink", nil
	case "unlink.file.filesystem":
		return "unlink", nil
	case "unlink.file.gid":
		return "unlink", nil
	case "unlink.file.group":
		return "unlink", nil
	case "unlink.file.in_upper_layer":
		return "unlink", nil
	case "unlink.file.inode":
		return "unlink", nil
	case "unlink.file.mode":
		return "unlink", nil
	case "unlink.file.modification_time":
		return "unlink", nil
	case "unlink.file.mount_id":
		return "unlink", nil
	case "unlink.file.name":
		return "unlink", nil
	case "unlink.file.name.length":
		return "unlink", nil
	case "unlink.file.package.name":
		return "unlink", nil
	case "unlink.file.package.source_version":
		return "unlink", nil
	case "unlink.file.package.version":
		return "unlink", nil
	case "unlink.file.path":
		return "unlink", nil
	case "unlink.file.path.length":
		return "unlink", nil
	case "unlink.file.rights":
		return "unlink", nil
	case "unlink.file.uid":
		return "unlink", nil
	case "unlink.file.user":
		return "unlink", nil
	case "unlink.flags":
		return "unlink", nil
	case "unlink.retval":
		return "unlink", nil
	case "unload_module.name":
		return "unload_module", nil
	case "unload_module.retval":
		return "unload_module", nil
	case "utimes.file.change_time":
		return "utimes", nil
	case "utimes.file.filesystem":
		return "utimes", nil
	case "utimes.file.gid":
		return "utimes", nil
	case "utimes.file.group":
		return "utimes", nil
	case "utimes.file.in_upper_layer":
		return "utimes", nil
	case "utimes.file.inode":
		return "utimes", nil
	case "utimes.file.mode":
		return "utimes", nil
	case "utimes.file.modification_time":
		return "utimes", nil
	case "utimes.file.mount_id":
		return "utimes", nil
	case "utimes.file.name":
		return "utimes", nil
	case "utimes.file.name.length":
		return "utimes", nil
	case "utimes.file.package.name":
		return "utimes", nil
	case "utimes.file.package.source_version":
		return "utimes", nil
	case "utimes.file.package.version":
		return "utimes", nil
	case "utimes.file.path":
		return "utimes", nil
	case "utimes.file.path.length":
		return "utimes", nil
	case "utimes.file.rights":
		return "utimes", nil
	case "utimes.file.uid":
		return "utimes", nil
	case "utimes.file.user":
		return "utimes", nil
	case "utimes.retval":
		return "utimes", nil
	}
	return "", &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) GetFieldType(field eval.Field) (reflect.Kind, error) {
	switch field {
	case "bind.addr.family":
		return reflect.Int, nil
	case "bind.addr.ip":
		return reflect.Struct, nil
	case "bind.addr.port":
		return reflect.Int, nil
	case "bind.retval":
		return reflect.Int, nil
	case "bpf.cmd":
		return reflect.Int, nil
	case "bpf.map.name":
		return reflect.String, nil
	case "bpf.map.type":
		return reflect.Int, nil
	case "bpf.prog.attach_type":
		return reflect.Int, nil
	case "bpf.prog.helpers":
		return reflect.Int, nil
	case "bpf.prog.name":
		return reflect.String, nil
	case "bpf.prog.tag":
		return reflect.String, nil
	case "bpf.prog.type":
		return reflect.Int, nil
	case "bpf.retval":
		return reflect.Int, nil
	case "capset.cap_effective":
		return reflect.Int, nil
	case "capset.cap_permitted":
		return reflect.Int, nil
	case "chmod.file.change_time":
		return reflect.Int, nil
	case "chmod.file.destination.mode":
		return reflect.Int, nil
	case "chmod.file.destination.rights":
		return reflect.Int, nil
	case "chmod.file.filesystem":
		return reflect.String, nil
	case "chmod.file.gid":
		return reflect.Int, nil
	case "chmod.file.group":
		return reflect.String, nil
	case "chmod.file.in_upper_layer":
		return reflect.Bool, nil
	case "chmod.file.inode":
		return reflect.Int, nil
	case "chmod.file.mode":
		return reflect.Int, nil
	case "chmod.file.modification_time":
		return reflect.Int, nil
	case "chmod.file.mount_id":
		return reflect.Int, nil
	case "chmod.file.name":
		return reflect.String, nil
	case "chmod.file.name.length":
		return reflect.Int, nil
	case "chmod.file.package.name":
		return reflect.String, nil
	case "chmod.file.package.source_version":
		return reflect.String, nil
	case "chmod.file.package.version":
		return reflect.String, nil
	case "chmod.file.path":
		return reflect.String, nil
	case "chmod.file.path.length":
		return reflect.Int, nil
	case "chmod.file.rights":
		return reflect.Int, nil
	case "chmod.file.uid":
		return reflect.Int, nil
	case "chmod.file.user":
		return reflect.String, nil
	case "chmod.retval":
		return reflect.Int, nil
	case "chown.file.change_time":
		return reflect.Int, nil
	case "chown.file.destination.gid":
		return reflect.Int, nil
	case "chown.file.destination.group":
		return reflect.String, nil
	case "chown.file.destination.uid":
		return reflect.Int, nil
	case "chown.file.destination.user":
		return reflect.String, nil
	case "chown.file.filesystem":
		return reflect.String, nil
	case "chown.file.gid":
		return reflect.Int, nil
	case "chown.file.group":
		return reflect.String, nil
	case "chown.file.in_upper_layer":
		return reflect.Bool, nil
	case "chown.file.inode":
		return reflect.Int, nil
	case "chown.file.mode":
		return reflect.Int, nil
	case "chown.file.modification_time":
		return reflect.Int, nil
	case "chown.file.mount_id":
		return reflect.Int, nil
	case "chown.file.name":
		return reflect.String, nil
	case "chown.file.name.length":
		return reflect.Int, nil
	case "chown.file.package.name":
		return reflect.String, nil
	case "chown.file.package.source_version":
		return reflect.String, nil
	case "chown.file.package.version":
		return reflect.String, nil
	case "chown.file.path":
		return reflect.String, nil
	case "chown.file.path.length":
		return reflect.Int, nil
	case "chown.file.rights":
		return reflect.Int, nil
	case "chown.file.uid":
		return reflect.Int, nil
	case "chown.file.user":
		return reflect.String, nil
	case "chown.retval":
		return reflect.Int, nil
	case "dns.id":
		return reflect.Int, nil
	case "dns.question.class":
		return reflect.Int, nil
	case "dns.question.count":
		return reflect.Int, nil
	case "dns.question.length":
		return reflect.Int, nil
	case "dns.question.name":
		return reflect.String, nil
	case "dns.question.name.length":
		return reflect.Int, nil
	case "dns.question.type":
		return reflect.Int, nil
	case "event.async":
		return reflect.Bool, nil
	case "exec.args":
		return reflect.String, nil
	case "exec.args_flags":
		return reflect.String, nil
	case "exec.args_options":
		return reflect.String, nil
	case "exec.args_truncated":
		return reflect.Bool, nil
	case "exec.argv":
		return reflect.String, nil
	case "exec.argv0":
		return reflect.String, nil
	case "exec.cap_effective":
		return reflect.Int, nil
	case "exec.cap_permitted":
		return reflect.Int, nil
	case "exec.comm":
		return reflect.String, nil
	case "exec.container.id":
		return reflect.String, nil
	case "exec.created_at":
		return reflect.Int, nil
	case "exec.egid":
		return reflect.Int, nil
	case "exec.egroup":
		return reflect.String, nil
	case "exec.envp":
		return reflect.String, nil
	case "exec.envs":
		return reflect.String, nil
	case "exec.envs_truncated":
		return reflect.Bool, nil
	case "exec.euid":
		return reflect.Int, nil
	case "exec.euser":
		return reflect.String, nil
	case "exec.file.change_time":
		return reflect.Int, nil
	case "exec.file.filesystem":
		return reflect.String, nil
	case "exec.file.gid":
		return reflect.Int, nil
	case "exec.file.group":
		return reflect.String, nil
	case "exec.file.in_upper_layer":
		return reflect.Bool, nil
	case "exec.file.inode":
		return reflect.Int, nil
	case "exec.file.mode":
		return reflect.Int, nil
	case "exec.file.modification_time":
		return reflect.Int, nil
	case "exec.file.mount_id":
		return reflect.Int, nil
	case "exec.file.name":
		return reflect.String, nil
	case "exec.file.name.length":
		return reflect.Int, nil
	case "exec.file.package.name":
		return reflect.String, nil
	case "exec.file.package.source_version":
		return reflect.String, nil
	case "exec.file.package.version":
		return reflect.String, nil
	case "exec.file.path":
		return reflect.String, nil
	case "exec.file.path.length":
		return reflect.Int, nil
	case "exec.file.rights":
		return reflect.Int, nil
	case "exec.file.uid":
		return reflect.Int, nil
	case "exec.file.user":
		return reflect.String, nil
	case "exec.fsgid":
		return reflect.Int, nil
	case "exec.fsgroup":
		return reflect.String, nil
	case "exec.fsuid":
		return reflect.Int, nil
	case "exec.fsuser":
		return reflect.String, nil
	case "exec.gid":
		return reflect.Int, nil
	case "exec.group":
		return reflect.String, nil
	case "exec.interpreter.file.change_time":
		return reflect.Int, nil
	case "exec.interpreter.file.filesystem":
		return reflect.String, nil
	case "exec.interpreter.file.gid":
		return reflect.Int, nil
	case "exec.interpreter.file.group":
		return reflect.String, nil
	case "exec.interpreter.file.in_upper_layer":
		return reflect.Bool, nil
	case "exec.interpreter.file.inode":
		return reflect.Int, nil
	case "exec.interpreter.file.mode":
		return reflect.Int, nil
	case "exec.interpreter.file.modification_time":
		return reflect.Int, nil
	case "exec.interpreter.file.mount_id":
		return reflect.Int, nil
	case "exec.interpreter.file.name":
		return reflect.String, nil
	case "exec.interpreter.file.name.length":
		return reflect.Int, nil
	case "exec.interpreter.file.package.name":
		return reflect.String, nil
	case "exec.interpreter.file.package.source_version":
		return reflect.String, nil
	case "exec.interpreter.file.package.version":
		return reflect.String, nil
	case "exec.interpreter.file.path":
		return reflect.String, nil
	case "exec.interpreter.file.path.length":
		return reflect.Int, nil
	case "exec.interpreter.file.rights":
		return reflect.Int, nil
	case "exec.interpreter.file.uid":
		return reflect.Int, nil
	case "exec.interpreter.file.user":
		return reflect.String, nil
	case "exec.is_kworker":
		return reflect.Bool, nil
	case "exec.is_thread":
		return reflect.Bool, nil
	case "exec.pid":
		return reflect.Int, nil
	case "exec.ppid":
		return reflect.Int, nil
	case "exec.tid":
		return reflect.Int, nil
	case "exec.tty_name":
		return reflect.String, nil
	case "exec.uid":
		return reflect.Int, nil
	case "exec.user":
		return reflect.String, nil
	case "exit.args":
		return reflect.String, nil
	case "exit.args_flags":
		return reflect.String, nil
	case "exit.args_options":
		return reflect.String, nil
	case "exit.args_truncated":
		return reflect.Bool, nil
	case "exit.argv":
		return reflect.String, nil
	case "exit.argv0":
		return reflect.String, nil
	case "exit.cap_effective":
		return reflect.Int, nil
	case "exit.cap_permitted":
		return reflect.Int, nil
	case "exit.cause":
		return reflect.Int, nil
	case "exit.code":
		return reflect.Int, nil
	case "exit.comm":
		return reflect.String, nil
	case "exit.container.id":
		return reflect.String, nil
	case "exit.created_at":
		return reflect.Int, nil
	case "exit.egid":
		return reflect.Int, nil
	case "exit.egroup":
		return reflect.String, nil
	case "exit.envp":
		return reflect.String, nil
	case "exit.envs":
		return reflect.String, nil
	case "exit.envs_truncated":
		return reflect.Bool, nil
	case "exit.euid":
		return reflect.Int, nil
	case "exit.euser":
		return reflect.String, nil
	case "exit.file.change_time":
		return reflect.Int, nil
	case "exit.file.filesystem":
		return reflect.String, nil
	case "exit.file.gid":
		return reflect.Int, nil
	case "exit.file.group":
		return reflect.String, nil
	case "exit.file.in_upper_layer":
		return reflect.Bool, nil
	case "exit.file.inode":
		return reflect.Int, nil
	case "exit.file.mode":
		return reflect.Int, nil
	case "exit.file.modification_time":
		return reflect.Int, nil
	case "exit.file.mount_id":
		return reflect.Int, nil
	case "exit.file.name":
		return reflect.String, nil
	case "exit.file.name.length":
		return reflect.Int, nil
	case "exit.file.package.name":
		return reflect.String, nil
	case "exit.file.package.source_version":
		return reflect.String, nil
	case "exit.file.package.version":
		return reflect.String, nil
	case "exit.file.path":
		return reflect.String, nil
	case "exit.file.path.length":
		return reflect.Int, nil
	case "exit.file.rights":
		return reflect.Int, nil
	case "exit.file.uid":
		return reflect.Int, nil
	case "exit.file.user":
		return reflect.String, nil
	case "exit.fsgid":
		return reflect.Int, nil
	case "exit.fsgroup":
		return reflect.String, nil
	case "exit.fsuid":
		return reflect.Int, nil
	case "exit.fsuser":
		return reflect.String, nil
	case "exit.gid":
		return reflect.Int, nil
	case "exit.group":
		return reflect.String, nil
	case "exit.interpreter.file.change_time":
		return reflect.Int, nil
	case "exit.interpreter.file.filesystem":
		return reflect.String, nil
	case "exit.interpreter.file.gid":
		return reflect.Int, nil
	case "exit.interpreter.file.group":
		return reflect.String, nil
	case "exit.interpreter.file.in_upper_layer":
		return reflect.Bool, nil
	case "exit.interpreter.file.inode":
		return reflect.Int, nil
	case "exit.interpreter.file.mode":
		return reflect.Int, nil
	case "exit.interpreter.file.modification_time":
		return reflect.Int, nil
	case "exit.interpreter.file.mount_id":
		return reflect.Int, nil
	case "exit.interpreter.file.name":
		return reflect.String, nil
	case "exit.interpreter.file.name.length":
		return reflect.Int, nil
	case "exit.interpreter.file.package.name":
		return reflect.String, nil
	case "exit.interpreter.file.package.source_version":
		return reflect.String, nil
	case "exit.interpreter.file.package.version":
		return reflect.String, nil
	case "exit.interpreter.file.path":
		return reflect.String, nil
	case "exit.interpreter.file.path.length":
		return reflect.Int, nil
	case "exit.interpreter.file.rights":
		return reflect.Int, nil
	case "exit.interpreter.file.uid":
		return reflect.Int, nil
	case "exit.interpreter.file.user":
		return reflect.String, nil
	case "exit.is_kworker":
		return reflect.Bool, nil
	case "exit.is_thread":
		return reflect.Bool, nil
	case "exit.pid":
		return reflect.Int, nil
	case "exit.ppid":
		return reflect.Int, nil
	case "exit.tid":
		return reflect.Int, nil
	case "exit.tty_name":
		return reflect.String, nil
	case "exit.uid":
		return reflect.Int, nil
	case "exit.user":
		return reflect.String, nil
	case "link.file.change_time":
		return reflect.Int, nil
	case "link.file.destination.change_time":
		return reflect.Int, nil
	case "link.file.destination.filesystem":
		return reflect.String, nil
	case "link.file.destination.gid":
		return reflect.Int, nil
	case "link.file.destination.group":
		return reflect.String, nil
	case "link.file.destination.in_upper_layer":
		return reflect.Bool, nil
	case "link.file.destination.inode":
		return reflect.Int, nil
	case "link.file.destination.mode":
		return reflect.Int, nil
	case "link.file.destination.modification_time":
		return reflect.Int, nil
	case "link.file.destination.mount_id":
		return reflect.Int, nil
	case "link.file.destination.name":
		return reflect.String, nil
	case "link.file.destination.name.length":
		return reflect.Int, nil
	case "link.file.destination.package.name":
		return reflect.String, nil
	case "link.file.destination.package.source_version":
		return reflect.String, nil
	case "link.file.destination.package.version":
		return reflect.String, nil
	case "link.file.destination.path":
		return reflect.String, nil
	case "link.file.destination.path.length":
		return reflect.Int, nil
	case "link.file.destination.rights":
		return reflect.Int, nil
	case "link.file.destination.uid":
		return reflect.Int, nil
	case "link.file.destination.user":
		return reflect.String, nil
	case "link.file.filesystem":
		return reflect.String, nil
	case "link.file.gid":
		return reflect.Int, nil
	case "link.file.group":
		return reflect.String, nil
	case "link.file.in_upper_layer":
		return reflect.Bool, nil
	case "link.file.inode":
		return reflect.Int, nil
	case "link.file.mode":
		return reflect.Int, nil
	case "link.file.modification_time":
		return reflect.Int, nil
	case "link.file.mount_id":
		return reflect.Int, nil
	case "link.file.name":
		return reflect.String, nil
	case "link.file.name.length":
		return reflect.Int, nil
	case "link.file.package.name":
		return reflect.String, nil
	case "link.file.package.source_version":
		return reflect.String, nil
	case "link.file.package.version":
		return reflect.String, nil
	case "link.file.path":
		return reflect.String, nil
	case "link.file.path.length":
		return reflect.Int, nil
	case "link.file.rights":
		return reflect.Int, nil
	case "link.file.uid":
		return reflect.Int, nil
	case "link.file.user":
		return reflect.String, nil
	case "link.retval":
		return reflect.Int, nil
	case "load_module.args":
		return reflect.String, nil
	case "load_module.args_truncated":
		return reflect.Bool, nil
	case "load_module.argv":
		return reflect.String, nil
	case "load_module.file.change_time":
		return reflect.Int, nil
	case "load_module.file.filesystem":
		return reflect.String, nil
	case "load_module.file.gid":
		return reflect.Int, nil
	case "load_module.file.group":
		return reflect.String, nil
	case "load_module.file.in_upper_layer":
		return reflect.Bool, nil
	case "load_module.file.inode":
		return reflect.Int, nil
	case "load_module.file.mode":
		return reflect.Int, nil
	case "load_module.file.modification_time":
		return reflect.Int, nil
	case "load_module.file.mount_id":
		return reflect.Int, nil
	case "load_module.file.name":
		return reflect.String, nil
	case "load_module.file.name.length":
		return reflect.Int, nil
	case "load_module.file.package.name":
		return reflect.String, nil
	case "load_module.file.package.source_version":
		return reflect.String, nil
	case "load_module.file.package.version":
		return reflect.String, nil
	case "load_module.file.path":
		return reflect.String, nil
	case "load_module.file.path.length":
		return reflect.Int, nil
	case "load_module.file.rights":
		return reflect.Int, nil
	case "load_module.file.uid":
		return reflect.Int, nil
	case "load_module.file.user":
		return reflect.String, nil
	case "load_module.loaded_from_memory":
		return reflect.Bool, nil
	case "load_module.name":
		return reflect.String, nil
	case "load_module.retval":
		return reflect.Int, nil
	case "mkdir.file.change_time":
		return reflect.Int, nil
	case "mkdir.file.destination.mode":
		return reflect.Int, nil
	case "mkdir.file.destination.rights":
		return reflect.Int, nil
	case "mkdir.file.filesystem":
		return reflect.String, nil
	case "mkdir.file.gid":
		return reflect.Int, nil
	case "mkdir.file.group":
		return reflect.String, nil
	case "mkdir.file.in_upper_layer":
		return reflect.Bool, nil
	case "mkdir.file.inode":
		return reflect.Int, nil
	case "mkdir.file.mode":
		return reflect.Int, nil
	case "mkdir.file.modification_time":
		return reflect.Int, nil
	case "mkdir.file.mount_id":
		return reflect.Int, nil
	case "mkdir.file.name":
		return reflect.String, nil
	case "mkdir.file.name.length":
		return reflect.Int, nil
	case "mkdir.file.package.name":
		return reflect.String, nil
	case "mkdir.file.package.source_version":
		return reflect.String, nil
	case "mkdir.file.package.version":
		return reflect.String, nil
	case "mkdir.file.path":
		return reflect.String, nil
	case "mkdir.file.path.length":
		return reflect.Int, nil
	case "mkdir.file.rights":
		return reflect.Int, nil
	case "mkdir.file.uid":
		return reflect.Int, nil
	case "mkdir.file.user":
		return reflect.String, nil
	case "mkdir.retval":
		return reflect.Int, nil
	case "mmap.file.change_time":
		return reflect.Int, nil
	case "mmap.file.filesystem":
		return reflect.String, nil
	case "mmap.file.gid":
		return reflect.Int, nil
	case "mmap.file.group":
		return reflect.String, nil
	case "mmap.file.in_upper_layer":
		return reflect.Bool, nil
	case "mmap.file.inode":
		return reflect.Int, nil
	case "mmap.file.mode":
		return reflect.Int, nil
	case "mmap.file.modification_time":
		return reflect.Int, nil
	case "mmap.file.mount_id":
		return reflect.Int, nil
	case "mmap.file.name":
		return reflect.String, nil
	case "mmap.file.name.length":
		return reflect.Int, nil
	case "mmap.file.package.name":
		return reflect.String, nil
	case "mmap.file.package.source_version":
		return reflect.String, nil
	case "mmap.file.package.version":
		return reflect.String, nil
	case "mmap.file.path":
		return reflect.String, nil
	case "mmap.file.path.length":
		return reflect.Int, nil
	case "mmap.file.rights":
		return reflect.Int, nil
	case "mmap.file.uid":
		return reflect.Int, nil
	case "mmap.file.user":
		return reflect.String, nil
	case "mmap.flags":
		return reflect.Int, nil
	case "mmap.protection":
		return reflect.Int, nil
	case "mmap.retval":
		return reflect.Int, nil
	case "mount.fs_type":
		return reflect.String, nil
	case "mount.mountpoint.path":
		return reflect.String, nil
	case "mount.retval":
		return reflect.Int, nil
	case "mount.source.path":
		return reflect.String, nil
	case "mprotect.req_protection":
		return reflect.Int, nil
	case "mprotect.retval":
		return reflect.Int, nil
	case "mprotect.vm_protection":
		return reflect.Int, nil
	case "open.file.change_time":
		return reflect.Int, nil
	case "open.file.destination.mode":
		return reflect.Int, nil
	case "open.file.filesystem":
		return reflect.String, nil
	case "open.file.gid":
		return reflect.Int, nil
	case "open.file.group":
		return reflect.String, nil
	case "open.file.in_upper_layer":
		return reflect.Bool, nil
	case "open.file.inode":
		return reflect.Int, nil
	case "open.file.mode":
		return reflect.Int, nil
	case "open.file.modification_time":
		return reflect.Int, nil
	case "open.file.mount_id":
		return reflect.Int, nil
	case "open.file.name":
		return reflect.String, nil
	case "open.file.name.length":
		return reflect.Int, nil
	case "open.file.package.name":
		return reflect.String, nil
	case "open.file.package.source_version":
		return reflect.String, nil
	case "open.file.package.version":
		return reflect.String, nil
	case "open.file.path":
		return reflect.String, nil
	case "open.file.path.length":
		return reflect.Int, nil
	case "open.file.rights":
		return reflect.Int, nil
	case "open.file.uid":
		return reflect.Int, nil
	case "open.file.user":
		return reflect.String, nil
	case "open.flags":
		return reflect.Int, nil
	case "open.retval":
		return reflect.Int, nil
	case "ptrace.request":
		return reflect.Int, nil
	case "ptrace.retval":
		return reflect.Int, nil
	case "removexattr.file.change_time":
		return reflect.Int, nil
	case "removexattr.file.destination.name":
		return reflect.String, nil
	case "removexattr.file.destination.namespace":
		return reflect.String, nil
	case "removexattr.file.filesystem":
		return reflect.String, nil
	case "removexattr.file.gid":
		return reflect.Int, nil
	case "removexattr.file.group":
		return reflect.String, nil
	case "removexattr.file.in_upper_layer":
		return reflect.Bool, nil
	case "removexattr.file.inode":
		return reflect.Int, nil
	case "removexattr.file.mode":
		return reflect.Int, nil
	case "removexattr.file.modification_time":
		return reflect.Int, nil
	case "removexattr.file.mount_id":
		return reflect.Int, nil
	case "removexattr.file.name":
		return reflect.String, nil
	case "removexattr.file.name.length":
		return reflect.Int, nil
	case "removexattr.file.package.name":
		return reflect.String, nil
	case "removexattr.file.package.source_version":
		return reflect.String, nil
	case "removexattr.file.package.version":
		return reflect.String, nil
	case "removexattr.file.path":
		return reflect.String, nil
	case "removexattr.file.path.length":
		return reflect.Int, nil
	case "removexattr.file.rights":
		return reflect.Int, nil
	case "removexattr.file.uid":
		return reflect.Int, nil
	case "removexattr.file.user":
		return reflect.String, nil
	case "removexattr.retval":
		return reflect.Int, nil
	case "rename.file.change_time":
		return reflect.Int, nil
	case "rename.file.destination.change_time":
		return reflect.Int, nil
	case "rename.file.destination.filesystem":
		return reflect.String, nil
	case "rename.file.destination.gid":
		return reflect.Int, nil
	case "rename.file.destination.group":
		return reflect.String, nil
	case "rename.file.destination.in_upper_layer":
		return reflect.Bool, nil
	case "rename.file.destination.inode":
		return reflect.Int, nil
	case "rename.file.destination.mode":
		return reflect.Int, nil
	case "rename.file.destination.modification_time":
		return reflect.Int, nil
	case "rename.file.destination.mount_id":
		return reflect.Int, nil
	case "rename.file.destination.name":
		return reflect.String, nil
	case "rename.file.destination.name.length":
		return reflect.Int, nil
	case "rename.file.destination.package.name":
		return reflect.String, nil
	case "rename.file.destination.package.source_version":
		return reflect.String, nil
	case "rename.file.destination.package.version":
		return reflect.String, nil
	case "rename.file.destination.path":
		return reflect.String, nil
	case "rename.file.destination.path.length":
		return reflect.Int, nil
	case "rename.file.destination.rights":
		return reflect.Int, nil
	case "rename.file.destination.uid":
		return reflect.Int, nil
	case "rename.file.destination.user":
		return reflect.String, nil
	case "rename.file.filesystem":
		return reflect.String, nil
	case "rename.file.gid":
		return reflect.Int, nil
	case "rename.file.group":
		return reflect.String, nil
	case "rename.file.in_upper_layer":
		return reflect.Bool, nil
	case "rename.file.inode":
		return reflect.Int, nil
	case "rename.file.mode":
		return reflect.Int, nil
	case "rename.file.modification_time":
		return reflect.Int, nil
	case "rename.file.mount_id":
		return reflect.Int, nil
	case "rename.file.name":
		return reflect.String, nil
	case "rename.file.name.length":
		return reflect.Int, nil
	case "rename.file.package.name":
		return reflect.String, nil
	case "rename.file.package.source_version":
		return reflect.String, nil
	case "rename.file.package.version":
		return reflect.String, nil
	case "rename.file.path":
		return reflect.String, nil
	case "rename.file.path.length":
		return reflect.Int, nil
	case "rename.file.rights":
		return reflect.Int, nil
	case "rename.file.uid":
		return reflect.Int, nil
	case "rename.file.user":
		return reflect.String, nil
	case "rename.retval":
		return reflect.Int, nil
	case "rmdir.file.change_time":
		return reflect.Int, nil
	case "rmdir.file.filesystem":
		return reflect.String, nil
	case "rmdir.file.gid":
		return reflect.Int, nil
	case "rmdir.file.group":
		return reflect.String, nil
	case "rmdir.file.in_upper_layer":
		return reflect.Bool, nil
	case "rmdir.file.inode":
		return reflect.Int, nil
	case "rmdir.file.mode":
		return reflect.Int, nil
	case "rmdir.file.modification_time":
		return reflect.Int, nil
	case "rmdir.file.mount_id":
		return reflect.Int, nil
	case "rmdir.file.name":
		return reflect.String, nil
	case "rmdir.file.name.length":
		return reflect.Int, nil
	case "rmdir.file.package.name":
		return reflect.String, nil
	case "rmdir.file.package.source_version":
		return reflect.String, nil
	case "rmdir.file.package.version":
		return reflect.String, nil
	case "rmdir.file.path":
		return reflect.String, nil
	case "rmdir.file.path.length":
		return reflect.Int, nil
	case "rmdir.file.rights":
		return reflect.Int, nil
	case "rmdir.file.uid":
		return reflect.Int, nil
	case "rmdir.file.user":
		return reflect.String, nil
	case "rmdir.retval":
		return reflect.Int, nil
	case "selinux.bool.name":
		return reflect.String, nil
	case "selinux.bool.state":
		return reflect.String, nil
	case "selinux.bool_commit.state":
		return reflect.Bool, nil
	case "selinux.enforce.status":
		return reflect.String, nil
	case "setgid.egid":
		return reflect.Int, nil
	case "setgid.egroup":
		return reflect.String, nil
	case "setgid.fsgid":
		return reflect.Int, nil
	case "setgid.fsgroup":
		return reflect.String, nil
	case "setgid.gid":
		return reflect.Int, nil
	case "setgid.group":
		return reflect.String, nil
	case "setuid.euid":
		return reflect.Int, nil
	case "setuid.euser":
		return reflect.String, nil
	case "setuid.fsuid":
		return reflect.Int, nil
	case "setuid.fsuser":
		return reflect.String, nil
	case "setuid.uid":
		return reflect.Int, nil
	case "setuid.user":
		return reflect.String, nil
	case "setxattr.file.change_time":
		return reflect.Int, nil
	case "setxattr.file.destination.name":
		return reflect.String, nil
	case "setxattr.file.destination.namespace":
		return reflect.String, nil
	case "setxattr.file.filesystem":
		return reflect.String, nil
	case "setxattr.file.gid":
		return reflect.Int, nil
	case "setxattr.file.group":
		return reflect.String, nil
	case "setxattr.file.in_upper_layer":
		return reflect.Bool, nil
	case "setxattr.file.inode":
		return reflect.Int, nil
	case "setxattr.file.mode":
		return reflect.Int, nil
	case "setxattr.file.modification_time":
		return reflect.Int, nil
	case "setxattr.file.mount_id":
		return reflect.Int, nil
	case "setxattr.file.name":
		return reflect.String, nil
	case "setxattr.file.name.length":
		return reflect.Int, nil
	case "setxattr.file.package.name":
		return reflect.String, nil
	case "setxattr.file.package.source_version":
		return reflect.String, nil
	case "setxattr.file.package.version":
		return reflect.String, nil
	case "setxattr.file.path":
		return reflect.String, nil
	case "setxattr.file.path.length":
		return reflect.Int, nil
	case "setxattr.file.rights":
		return reflect.Int, nil
	case "setxattr.file.uid":
		return reflect.Int, nil
	case "setxattr.file.user":
		return reflect.String, nil
	case "setxattr.retval":
		return reflect.Int, nil
	case "signal.pid":
		return reflect.Int, nil
	case "signal.retval":
		return reflect.Int, nil
	case "signal.type":
		return reflect.Int, nil
	case "splice.file.change_time":
		return reflect.Int, nil
	case "splice.file.filesystem":
		return reflect.String, nil
	case "splice.file.gid":
		return reflect.Int, nil
	case "splice.file.group":
		return reflect.String, nil
	case "splice.file.in_upper_layer":
		return reflect.Bool, nil
	case "splice.file.inode":
		return reflect.Int, nil
	case "splice.file.mode":
		return reflect.Int, nil
	case "splice.file.modification_time":
		return reflect.Int, nil
	case "splice.file.mount_id":
		return reflect.Int, nil
	case "splice.file.name":
		return reflect.String, nil
	case "splice.file.name.length":
		return reflect.Int, nil
	case "splice.file.package.name":
		return reflect.String, nil
	case "splice.file.package.source_version":
		return reflect.String, nil
	case "splice.file.package.version":
		return reflect.String, nil
	case "splice.file.path":
		return reflect.String, nil
	case "splice.file.path.length":
		return reflect.Int, nil
	case "splice.file.rights":
		return reflect.Int, nil
	case "splice.file.uid":
		return reflect.Int, nil
	case "splice.file.user":
		return reflect.String, nil
	case "splice.pipe_entry_flag":
		return reflect.Int, nil
	case "splice.pipe_exit_flag":
		return reflect.Int, nil
	case "splice.retval":
		return reflect.Int, nil
	case "unlink.file.change_time":
		return reflect.Int, nil
	case "unlink.file.filesystem":
		return reflect.String, nil
	case "unlink.file.gid":
		return reflect.Int, nil
	case "unlink.file.group":
		return reflect.String, nil
	case "unlink.file.in_upper_layer":
		return reflect.Bool, nil
	case "unlink.file.inode":
		return reflect.Int, nil
	case "unlink.file.mode":
		return reflect.Int, nil
	case "unlink.file.modification_time":
		return reflect.Int, nil
	case "unlink.file.mount_id":
		return reflect.Int, nil
	case "unlink.file.name":
		return reflect.String, nil
	case "unlink.file.name.length":
		return reflect.Int, nil
	case "unlink.file.package.name":
		return reflect.String, nil
	case "unlink.file.package.source_version":
		return reflect.String, nil
	case "unlink.file.package.version":
		return reflect.String, nil
	case "unlink.file.path":
		return reflect.String, nil
	case "unlink.file.path.length":
		return reflect.Int, nil
	case "unlink.file.rights":
		return reflect.Int, nil
	case "unlink.file.uid":
		return reflect.Int, nil
	case "unlink.file.user":
		return reflect.String, nil
	case "unlink.flags":
		return reflect.Int, nil
	case "unlink.retval":
		return reflect.Int, nil
	case "unload_module.name":
		return reflect.String, nil
	case "unload_module.retval":
		return reflect.Int, nil
	case "utimes.file.change_time":
		return reflect.Int, nil
	case "utimes.file.filesystem":
		return reflect.String, nil
	case "utimes.file.gid":
		return reflect.Int, nil
	case "utimes.file.group":
		return reflect.String, nil
	case "utimes.file.in_upper_layer":
		return reflect.Bool, nil
	case "utimes.file.inode":
		return reflect.Int, nil
	case "utimes.file.mode":
		return reflect.Int, nil
	case "utimes.file.modification_time":
		return reflect.Int, nil
	case "utimes.file.mount_id":
		return reflect.Int, nil
	case "utimes.file.name":
		return reflect.String, nil
	case "utimes.file.name.length":
		return reflect.Int, nil
	case "utimes.file.package.name":
		return reflect.String, nil
	case "utimes.file.package.source_version":
		return reflect.String, nil
	case "utimes.file.package.version":
		return reflect.String, nil
	case "utimes.file.path":
		return reflect.String, nil
	case "utimes.file.path.length":
		return reflect.Int, nil
	case "utimes.file.rights":
		return reflect.Int, nil
	case "utimes.file.uid":
		return reflect.Int, nil
	case "utimes.file.user":
		return reflect.String, nil
	case "utimes.retval":
		return reflect.Int, nil
	}
	return reflect.Invalid, &eval.ErrFieldNotFound{Field: field}
}
func (ev *Event) SetFieldValue(field eval.Field, value interface{}) error {
	switch field {
	case "bind.addr.family":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Bind.AddrFamily"}
		}
		ev.Bind.AddrFamily = uint16(rv)
		return nil
	case "bind.addr.ip":
		rv, ok := value.(net.IPNet)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Bind.Addr.IPNet"}
		}
		ev.Bind.Addr.IPNet = rv
		return nil
	case "bind.addr.port":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Bind.Addr.Port"}
		}
		ev.Bind.Addr.Port = uint16(rv)
		return nil
	case "bind.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Bind.SyscallEvent.Retval"}
		}
		ev.Bind.SyscallEvent.Retval = int64(rv)
		return nil
	case "bpf.cmd":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Cmd"}
		}
		ev.BPF.Cmd = uint32(rv)
		return nil
	case "bpf.map.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Map.Name"}
		}
		ev.BPF.Map.Name = rv
		return nil
	case "bpf.map.type":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Map.Type"}
		}
		ev.BPF.Map.Type = uint32(rv)
		return nil
	case "bpf.prog.attach_type":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Program.AttachType"}
		}
		ev.BPF.Program.AttachType = uint32(rv)
		return nil
	case "bpf.prog.helpers":
		switch rv := value.(type) {
		case int:
			ev.BPF.Program.Helpers = append(ev.BPF.Program.Helpers, uint32(rv))
		case []int:
			for _, i := range rv {
				ev.BPF.Program.Helpers = append(ev.BPF.Program.Helpers, uint32(i))
			}
		default:
			return &eval.ErrValueTypeMismatch{Field: "BPF.Program.Helpers"}
		}
		return nil
	case "bpf.prog.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Program.Name"}
		}
		ev.BPF.Program.Name = rv
		return nil
	case "bpf.prog.tag":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Program.Tag"}
		}
		ev.BPF.Program.Tag = rv
		return nil
	case "bpf.prog.type":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.Program.Type"}
		}
		ev.BPF.Program.Type = uint32(rv)
		return nil
	case "bpf.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "BPF.SyscallEvent.Retval"}
		}
		ev.BPF.SyscallEvent.Retval = int64(rv)
		return nil
	case "capset.cap_effective":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Capset.CapEffective"}
		}
		ev.Capset.CapEffective = uint64(rv)
		return nil
	case "capset.cap_permitted":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Capset.CapPermitted"}
		}
		ev.Capset.CapPermitted = uint64(rv)
		return nil
	case "chmod.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.CTime"}
		}
		ev.Chmod.File.FileFields.CTime = uint64(rv)
		return nil
	case "chmod.file.destination.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.Mode"}
		}
		ev.Chmod.Mode = uint32(rv)
		return nil
	case "chmod.file.destination.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.Mode"}
		}
		ev.Chmod.Mode = uint32(rv)
		return nil
	case "chmod.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.Filesystem"}
		}
		ev.Chmod.File.Filesystem = rv
		return nil
	case "chmod.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.GID"}
		}
		ev.Chmod.File.FileFields.GID = uint32(rv)
		return nil
	case "chmod.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Group"}
		}
		ev.Chmod.File.FileFields.Group = rv
		return nil
	case "chmod.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.InUpperLayer"}
		}
		ev.Chmod.File.FileFields.InUpperLayer = rv
		return nil
	case "chmod.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.PathKey.Inode"}
		}
		ev.Chmod.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "chmod.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Mode"}
		}
		ev.Chmod.File.FileFields.Mode = uint16(rv)
		return nil
	case "chmod.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.MTime"}
		}
		ev.Chmod.File.FileFields.MTime = uint64(rv)
		return nil
	case "chmod.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.PathKey.MountID"}
		}
		ev.Chmod.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "chmod.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.BasenameStr"}
		}
		ev.Chmod.File.BasenameStr = rv
		return nil
	case "chmod.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "chmod.file.name.length"}
	case "chmod.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.PkgName"}
		}
		ev.Chmod.File.PkgName = rv
		return nil
	case "chmod.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.PkgSrcVersion"}
		}
		ev.Chmod.File.PkgSrcVersion = rv
		return nil
	case "chmod.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.PkgVersion"}
		}
		ev.Chmod.File.PkgVersion = rv
		return nil
	case "chmod.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.PathnameStr"}
		}
		ev.Chmod.File.PathnameStr = rv
		return nil
	case "chmod.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "chmod.file.path.length"}
	case "chmod.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.Mode"}
		}
		ev.Chmod.File.FileFields.Mode = uint16(rv)
		return nil
	case "chmod.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.UID"}
		}
		ev.Chmod.File.FileFields.UID = uint32(rv)
		return nil
	case "chmod.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.File.FileFields.User"}
		}
		ev.Chmod.File.FileFields.User = rv
		return nil
	case "chmod.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chmod.SyscallEvent.Retval"}
		}
		ev.Chmod.SyscallEvent.Retval = int64(rv)
		return nil
	case "chown.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.CTime"}
		}
		ev.Chown.File.FileFields.CTime = uint64(rv)
		return nil
	case "chown.file.destination.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.GID"}
		}
		ev.Chown.GID = int64(rv)
		return nil
	case "chown.file.destination.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.Group"}
		}
		ev.Chown.Group = rv
		return nil
	case "chown.file.destination.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.UID"}
		}
		ev.Chown.UID = int64(rv)
		return nil
	case "chown.file.destination.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.User"}
		}
		ev.Chown.User = rv
		return nil
	case "chown.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.Filesystem"}
		}
		ev.Chown.File.Filesystem = rv
		return nil
	case "chown.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.GID"}
		}
		ev.Chown.File.FileFields.GID = uint32(rv)
		return nil
	case "chown.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Group"}
		}
		ev.Chown.File.FileFields.Group = rv
		return nil
	case "chown.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.InUpperLayer"}
		}
		ev.Chown.File.FileFields.InUpperLayer = rv
		return nil
	case "chown.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.PathKey.Inode"}
		}
		ev.Chown.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "chown.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Mode"}
		}
		ev.Chown.File.FileFields.Mode = uint16(rv)
		return nil
	case "chown.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.MTime"}
		}
		ev.Chown.File.FileFields.MTime = uint64(rv)
		return nil
	case "chown.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.PathKey.MountID"}
		}
		ev.Chown.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "chown.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.BasenameStr"}
		}
		ev.Chown.File.BasenameStr = rv
		return nil
	case "chown.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "chown.file.name.length"}
	case "chown.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.PkgName"}
		}
		ev.Chown.File.PkgName = rv
		return nil
	case "chown.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.PkgSrcVersion"}
		}
		ev.Chown.File.PkgSrcVersion = rv
		return nil
	case "chown.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.PkgVersion"}
		}
		ev.Chown.File.PkgVersion = rv
		return nil
	case "chown.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.PathnameStr"}
		}
		ev.Chown.File.PathnameStr = rv
		return nil
	case "chown.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "chown.file.path.length"}
	case "chown.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.Mode"}
		}
		ev.Chown.File.FileFields.Mode = uint16(rv)
		return nil
	case "chown.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.UID"}
		}
		ev.Chown.File.FileFields.UID = uint32(rv)
		return nil
	case "chown.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.File.FileFields.User"}
		}
		ev.Chown.File.FileFields.User = rv
		return nil
	case "chown.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Chown.SyscallEvent.Retval"}
		}
		ev.Chown.SyscallEvent.Retval = int64(rv)
		return nil
	case "dns.id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.ID"}
		}
		ev.DNS.ID = uint16(rv)
		return nil
	case "dns.question.class":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.Class"}
		}
		ev.DNS.Class = uint16(rv)
		return nil
	case "dns.question.count":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.Count"}
		}
		ev.DNS.Count = uint16(rv)
		return nil
	case "dns.question.length":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.Size"}
		}
		ev.DNS.Size = uint16(rv)
		return nil
	case "dns.question.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.Name"}
		}
		ev.DNS.Name = rv
		return nil
	case "dns.question.name.length":
		return &eval.ErrFieldReadOnly{Field: "dns.question.name.length"}
	case "dns.question.type":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "DNS.Type"}
		}
		ev.DNS.Type = uint16(rv)
		return nil
	case "event.async":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Async"}
		}
		ev.Async = rv
		return nil
	case "exec.args":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Args"}
		}
		ev.Exec.Process.Args = rv
		return nil
	case "exec.args_flags":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.args_options":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.args_truncated":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.ArgsTruncated"}
		}
		ev.Exec.Process.ArgsTruncated = rv
		return nil
	case "exec.argv":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv)
		case []string:
			ev.Exec.Process.Argv = append(ev.Exec.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv"}
		}
		return nil
	case "exec.argv0":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Argv0"}
		}
		ev.Exec.Process.Argv0 = rv
		return nil
	case "exec.cap_effective":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapEffective"}
		}
		ev.Exec.Process.Credentials.CapEffective = uint64(rv)
		return nil
	case "exec.cap_permitted":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.CapPermitted"}
		}
		ev.Exec.Process.Credentials.CapPermitted = uint64(rv)
		return nil
	case "exec.comm":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Comm"}
		}
		ev.Exec.Process.Comm = rv
		return nil
	case "exec.container.id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.ContainerID"}
		}
		ev.Exec.Process.ContainerID = rv
		return nil
	case "exec.created_at":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.CreatedAt"}
		}
		ev.Exec.Process.CreatedAt = uint64(rv)
		return nil
	case "exec.egid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGID"}
		}
		ev.Exec.Process.Credentials.EGID = uint32(rv)
		return nil
	case "exec.egroup":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EGroup"}
		}
		ev.Exec.Process.Credentials.EGroup = rv
		return nil
	case "exec.envp":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Envp = append(ev.Exec.Process.Envp, rv)
		case []string:
			ev.Exec.Process.Envp = append(ev.Exec.Process.Envp, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Envp"}
		}
		return nil
	case "exec.envs":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exec.Process.Envs = append(ev.Exec.Process.Envs, rv)
		case []string:
			ev.Exec.Process.Envs = append(ev.Exec.Process.Envs, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Envs"}
		}
		return nil
	case "exec.envs_truncated":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.EnvsTruncated"}
		}
		ev.Exec.Process.EnvsTruncated = rv
		return nil
	case "exec.euid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUID"}
		}
		ev.Exec.Process.Credentials.EUID = uint32(rv)
		return nil
	case "exec.euser":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.EUser"}
		}
		ev.Exec.Process.Credentials.EUser = rv
		return nil
	case "exec.file.change_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.CTime"}
		}
		ev.Exec.Process.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exec.file.filesystem":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.Filesystem"}
		}
		ev.Exec.Process.FileEvent.Filesystem = rv
		return nil
	case "exec.file.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.GID"}
		}
		ev.Exec.Process.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exec.file.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Group"}
		}
		ev.Exec.Process.FileEvent.FileFields.Group = rv
		return nil
	case "exec.file.in_upper_layer":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exec.Process.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exec.file.inode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exec.Process.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exec.file.mode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.file.modification_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.MTime"}
		}
		ev.Exec.Process.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exec.file.mount_id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exec.Process.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exec.file.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.BasenameStr"}
		}
		ev.Exec.Process.FileEvent.BasenameStr = rv
		return nil
	case "exec.file.name.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.file.name.length"}
	case "exec.file.package.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgName"}
		}
		ev.Exec.Process.FileEvent.PkgName = rv
		return nil
	case "exec.file.package.source_version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgSrcVersion"}
		}
		ev.Exec.Process.FileEvent.PkgSrcVersion = rv
		return nil
	case "exec.file.package.version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PkgVersion"}
		}
		ev.Exec.Process.FileEvent.PkgVersion = rv
		return nil
	case "exec.file.path":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.PathnameStr"}
		}
		ev.Exec.Process.FileEvent.PathnameStr = rv
		return nil
	case "exec.file.path.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.file.path.length"}
	case "exec.file.rights":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.file.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.UID"}
		}
		ev.Exec.Process.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exec.file.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.FileEvent.FileFields.User"}
		}
		ev.Exec.Process.FileEvent.FileFields.User = rv
		return nil
	case "exec.fsgid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGID"}
		}
		ev.Exec.Process.Credentials.FSGID = uint32(rv)
		return nil
	case "exec.fsgroup":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSGroup"}
		}
		ev.Exec.Process.Credentials.FSGroup = rv
		return nil
	case "exec.fsuid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUID"}
		}
		ev.Exec.Process.Credentials.FSUID = uint32(rv)
		return nil
	case "exec.fsuser":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.FSUser"}
		}
		ev.Exec.Process.Credentials.FSUser = rv
		return nil
	case "exec.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.GID"}
		}
		ev.Exec.Process.Credentials.GID = uint32(rv)
		return nil
	case "exec.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.Group"}
		}
		ev.Exec.Process.Credentials.Group = rv
		return nil
	case "exec.interpreter.file.change_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exec.interpreter.file.filesystem":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.Filesystem"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.Filesystem = rv
		return nil
	case "exec.interpreter.file.gid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.GID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exec.interpreter.file.group":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Group"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Group = rv
		return nil
	case "exec.interpreter.file.in_upper_layer":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exec.interpreter.file.inode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exec.interpreter.file.mode":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.interpreter.file.modification_time":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exec.interpreter.file.mount_id":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exec.interpreter.file.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.BasenameStr"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.BasenameStr = rv
		return nil
	case "exec.interpreter.file.name.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.interpreter.file.name.length"}
	case "exec.interpreter.file.package.name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgName"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgName = rv
		return nil
	case "exec.interpreter.file.package.source_version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgSrcVersion"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgSrcVersion = rv
		return nil
	case "exec.interpreter.file.package.version":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PkgVersion"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PkgVersion = rv
		return nil
	case "exec.interpreter.file.path":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.PathnameStr"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.PathnameStr = rv
		return nil
	case "exec.interpreter.file.path.length":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exec.interpreter.file.path.length"}
	case "exec.interpreter.file.rights":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exec.interpreter.file.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.UID"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exec.interpreter.file.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.LinuxBinprm.FileEvent.FileFields.User"}
		}
		ev.Exec.Process.LinuxBinprm.FileEvent.FileFields.User = rv
		return nil
	case "exec.is_kworker":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.IsKworker"}
		}
		ev.Exec.Process.PIDContext.IsKworker = rv
		return nil
	case "exec.is_thread":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.IsThread"}
		}
		ev.Exec.Process.IsThread = rv
		return nil
	case "exec.pid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.Pid"}
		}
		ev.Exec.Process.PIDContext.Pid = uint32(rv)
		return nil
	case "exec.ppid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PPid"}
		}
		ev.Exec.Process.PPid = uint32(rv)
		return nil
	case "exec.tid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.PIDContext.Tid"}
		}
		ev.Exec.Process.PIDContext.Tid = uint32(rv)
		return nil
	case "exec.tty_name":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.TTYName"}
		}
		ev.Exec.Process.TTYName = rv
		return nil
	case "exec.uid":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.UID"}
		}
		ev.Exec.Process.Credentials.UID = uint32(rv)
		return nil
	case "exec.user":
		if ev.Exec.Process == nil {
			ev.Exec.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exec.Process.Credentials.User"}
		}
		ev.Exec.Process.Credentials.User = rv
		return nil
	case "exit.args":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Args"}
		}
		ev.Exit.Process.Args = rv
		return nil
	case "exit.args_flags":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.args_options":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.args_truncated":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.ArgsTruncated"}
		}
		ev.Exit.Process.ArgsTruncated = rv
		return nil
	case "exit.argv":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv)
		case []string:
			ev.Exit.Process.Argv = append(ev.Exit.Process.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv"}
		}
		return nil
	case "exit.argv0":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Argv0"}
		}
		ev.Exit.Process.Argv0 = rv
		return nil
	case "exit.cap_effective":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.CapEffective"}
		}
		ev.Exit.Process.Credentials.CapEffective = uint64(rv)
		return nil
	case "exit.cap_permitted":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.CapPermitted"}
		}
		ev.Exit.Process.Credentials.CapPermitted = uint64(rv)
		return nil
	case "exit.cause":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Cause"}
		}
		ev.Exit.Cause = uint32(rv)
		return nil
	case "exit.code":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Code"}
		}
		ev.Exit.Code = uint32(rv)
		return nil
	case "exit.comm":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Comm"}
		}
		ev.Exit.Process.Comm = rv
		return nil
	case "exit.container.id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.ContainerID"}
		}
		ev.Exit.Process.ContainerID = rv
		return nil
	case "exit.created_at":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.CreatedAt"}
		}
		ev.Exit.Process.CreatedAt = uint64(rv)
		return nil
	case "exit.egid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EGID"}
		}
		ev.Exit.Process.Credentials.EGID = uint32(rv)
		return nil
	case "exit.egroup":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EGroup"}
		}
		ev.Exit.Process.Credentials.EGroup = rv
		return nil
	case "exit.envp":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Envp = append(ev.Exit.Process.Envp, rv)
		case []string:
			ev.Exit.Process.Envp = append(ev.Exit.Process.Envp, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Envp"}
		}
		return nil
	case "exit.envs":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		switch rv := value.(type) {
		case string:
			ev.Exit.Process.Envs = append(ev.Exit.Process.Envs, rv)
		case []string:
			ev.Exit.Process.Envs = append(ev.Exit.Process.Envs, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Envs"}
		}
		return nil
	case "exit.envs_truncated":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.EnvsTruncated"}
		}
		ev.Exit.Process.EnvsTruncated = rv
		return nil
	case "exit.euid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EUID"}
		}
		ev.Exit.Process.Credentials.EUID = uint32(rv)
		return nil
	case "exit.euser":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.EUser"}
		}
		ev.Exit.Process.Credentials.EUser = rv
		return nil
	case "exit.file.change_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.CTime"}
		}
		ev.Exit.Process.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exit.file.filesystem":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.Filesystem"}
		}
		ev.Exit.Process.FileEvent.Filesystem = rv
		return nil
	case "exit.file.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.GID"}
		}
		ev.Exit.Process.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exit.file.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Group"}
		}
		ev.Exit.Process.FileEvent.FileFields.Group = rv
		return nil
	case "exit.file.in_upper_layer":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exit.Process.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exit.file.inode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exit.Process.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exit.file.mode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.file.modification_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.MTime"}
		}
		ev.Exit.Process.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exit.file.mount_id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exit.Process.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exit.file.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.BasenameStr"}
		}
		ev.Exit.Process.FileEvent.BasenameStr = rv
		return nil
	case "exit.file.name.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.file.name.length"}
	case "exit.file.package.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgName"}
		}
		ev.Exit.Process.FileEvent.PkgName = rv
		return nil
	case "exit.file.package.source_version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgSrcVersion"}
		}
		ev.Exit.Process.FileEvent.PkgSrcVersion = rv
		return nil
	case "exit.file.package.version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PkgVersion"}
		}
		ev.Exit.Process.FileEvent.PkgVersion = rv
		return nil
	case "exit.file.path":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.PathnameStr"}
		}
		ev.Exit.Process.FileEvent.PathnameStr = rv
		return nil
	case "exit.file.path.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.file.path.length"}
	case "exit.file.rights":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.file.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.UID"}
		}
		ev.Exit.Process.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exit.file.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.FileEvent.FileFields.User"}
		}
		ev.Exit.Process.FileEvent.FileFields.User = rv
		return nil
	case "exit.fsgid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSGID"}
		}
		ev.Exit.Process.Credentials.FSGID = uint32(rv)
		return nil
	case "exit.fsgroup":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSGroup"}
		}
		ev.Exit.Process.Credentials.FSGroup = rv
		return nil
	case "exit.fsuid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSUID"}
		}
		ev.Exit.Process.Credentials.FSUID = uint32(rv)
		return nil
	case "exit.fsuser":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.FSUser"}
		}
		ev.Exit.Process.Credentials.FSUser = rv
		return nil
	case "exit.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.GID"}
		}
		ev.Exit.Process.Credentials.GID = uint32(rv)
		return nil
	case "exit.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.Group"}
		}
		ev.Exit.Process.Credentials.Group = rv
		return nil
	case "exit.interpreter.file.change_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.CTime = uint64(rv)
		return nil
	case "exit.interpreter.file.filesystem":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.Filesystem"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.Filesystem = rv
		return nil
	case "exit.interpreter.file.gid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.GID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.GID = uint32(rv)
		return nil
	case "exit.interpreter.file.group":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Group"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Group = rv
		return nil
	case "exit.interpreter.file.in_upper_layer":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.InUpperLayer = rv
		return nil
	case "exit.interpreter.file.inode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "exit.interpreter.file.mode":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.interpreter.file.modification_time":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.MTime = uint64(rv)
		return nil
	case "exit.interpreter.file.mount_id":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "exit.interpreter.file.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.BasenameStr"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.BasenameStr = rv
		return nil
	case "exit.interpreter.file.name.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.interpreter.file.name.length"}
	case "exit.interpreter.file.package.name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgName"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgName = rv
		return nil
	case "exit.interpreter.file.package.source_version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgSrcVersion"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgSrcVersion = rv
		return nil
	case "exit.interpreter.file.package.version":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PkgVersion"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PkgVersion = rv
		return nil
	case "exit.interpreter.file.path":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.PathnameStr"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.PathnameStr = rv
		return nil
	case "exit.interpreter.file.path.length":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		return &eval.ErrFieldReadOnly{Field: "exit.interpreter.file.path.length"}
	case "exit.interpreter.file.rights":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.Mode = uint16(rv)
		return nil
	case "exit.interpreter.file.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.UID"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.UID = uint32(rv)
		return nil
	case "exit.interpreter.file.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.LinuxBinprm.FileEvent.FileFields.User"}
		}
		ev.Exit.Process.LinuxBinprm.FileEvent.FileFields.User = rv
		return nil
	case "exit.is_kworker":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.IsKworker"}
		}
		ev.Exit.Process.PIDContext.IsKworker = rv
		return nil
	case "exit.is_thread":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.IsThread"}
		}
		ev.Exit.Process.IsThread = rv
		return nil
	case "exit.pid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.Pid"}
		}
		ev.Exit.Process.PIDContext.Pid = uint32(rv)
		return nil
	case "exit.ppid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PPid"}
		}
		ev.Exit.Process.PPid = uint32(rv)
		return nil
	case "exit.tid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.PIDContext.Tid"}
		}
		ev.Exit.Process.PIDContext.Tid = uint32(rv)
		return nil
	case "exit.tty_name":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.TTYName"}
		}
		ev.Exit.Process.TTYName = rv
		return nil
	case "exit.uid":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.UID"}
		}
		ev.Exit.Process.Credentials.UID = uint32(rv)
		return nil
	case "exit.user":
		if ev.Exit.Process == nil {
			ev.Exit.Process = &Process{}
		}
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Exit.Process.Credentials.User"}
		}
		ev.Exit.Process.Credentials.User = rv
		return nil
	case "link.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.CTime"}
		}
		ev.Link.Source.FileFields.CTime = uint64(rv)
		return nil
	case "link.file.destination.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.CTime"}
		}
		ev.Link.Target.FileFields.CTime = uint64(rv)
		return nil
	case "link.file.destination.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.Filesystem"}
		}
		ev.Link.Target.Filesystem = rv
		return nil
	case "link.file.destination.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.GID"}
		}
		ev.Link.Target.FileFields.GID = uint32(rv)
		return nil
	case "link.file.destination.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Group"}
		}
		ev.Link.Target.FileFields.Group = rv
		return nil
	case "link.file.destination.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.InUpperLayer"}
		}
		ev.Link.Target.FileFields.InUpperLayer = rv
		return nil
	case "link.file.destination.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.PathKey.Inode"}
		}
		ev.Link.Target.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "link.file.destination.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Mode"}
		}
		ev.Link.Target.FileFields.Mode = uint16(rv)
		return nil
	case "link.file.destination.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.MTime"}
		}
		ev.Link.Target.FileFields.MTime = uint64(rv)
		return nil
	case "link.file.destination.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.PathKey.MountID"}
		}
		ev.Link.Target.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "link.file.destination.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.BasenameStr"}
		}
		ev.Link.Target.BasenameStr = rv
		return nil
	case "link.file.destination.name.length":
		return &eval.ErrFieldReadOnly{Field: "link.file.destination.name.length"}
	case "link.file.destination.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.PkgName"}
		}
		ev.Link.Target.PkgName = rv
		return nil
	case "link.file.destination.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.PkgSrcVersion"}
		}
		ev.Link.Target.PkgSrcVersion = rv
		return nil
	case "link.file.destination.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.PkgVersion"}
		}
		ev.Link.Target.PkgVersion = rv
		return nil
	case "link.file.destination.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.PathnameStr"}
		}
		ev.Link.Target.PathnameStr = rv
		return nil
	case "link.file.destination.path.length":
		return &eval.ErrFieldReadOnly{Field: "link.file.destination.path.length"}
	case "link.file.destination.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.Mode"}
		}
		ev.Link.Target.FileFields.Mode = uint16(rv)
		return nil
	case "link.file.destination.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.UID"}
		}
		ev.Link.Target.FileFields.UID = uint32(rv)
		return nil
	case "link.file.destination.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Target.FileFields.User"}
		}
		ev.Link.Target.FileFields.User = rv
		return nil
	case "link.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.Filesystem"}
		}
		ev.Link.Source.Filesystem = rv
		return nil
	case "link.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.GID"}
		}
		ev.Link.Source.FileFields.GID = uint32(rv)
		return nil
	case "link.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Group"}
		}
		ev.Link.Source.FileFields.Group = rv
		return nil
	case "link.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.InUpperLayer"}
		}
		ev.Link.Source.FileFields.InUpperLayer = rv
		return nil
	case "link.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.PathKey.Inode"}
		}
		ev.Link.Source.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "link.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Mode"}
		}
		ev.Link.Source.FileFields.Mode = uint16(rv)
		return nil
	case "link.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.MTime"}
		}
		ev.Link.Source.FileFields.MTime = uint64(rv)
		return nil
	case "link.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.PathKey.MountID"}
		}
		ev.Link.Source.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "link.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.BasenameStr"}
		}
		ev.Link.Source.BasenameStr = rv
		return nil
	case "link.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "link.file.name.length"}
	case "link.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.PkgName"}
		}
		ev.Link.Source.PkgName = rv
		return nil
	case "link.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.PkgSrcVersion"}
		}
		ev.Link.Source.PkgSrcVersion = rv
		return nil
	case "link.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.PkgVersion"}
		}
		ev.Link.Source.PkgVersion = rv
		return nil
	case "link.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.PathnameStr"}
		}
		ev.Link.Source.PathnameStr = rv
		return nil
	case "link.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "link.file.path.length"}
	case "link.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.Mode"}
		}
		ev.Link.Source.FileFields.Mode = uint16(rv)
		return nil
	case "link.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.UID"}
		}
		ev.Link.Source.FileFields.UID = uint32(rv)
		return nil
	case "link.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.Source.FileFields.User"}
		}
		ev.Link.Source.FileFields.User = rv
		return nil
	case "link.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Link.SyscallEvent.Retval"}
		}
		ev.Link.SyscallEvent.Retval = int64(rv)
		return nil
	case "load_module.args":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.Args"}
		}
		ev.LoadModule.Args = rv
		return nil
	case "load_module.args_truncated":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.ArgsTruncated"}
		}
		ev.LoadModule.ArgsTruncated = rv
		return nil
	case "load_module.argv":
		switch rv := value.(type) {
		case string:
			ev.LoadModule.Argv = append(ev.LoadModule.Argv, rv)
		case []string:
			ev.LoadModule.Argv = append(ev.LoadModule.Argv, rv...)
		default:
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.Argv"}
		}
		return nil
	case "load_module.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.CTime"}
		}
		ev.LoadModule.File.FileFields.CTime = uint64(rv)
		return nil
	case "load_module.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.Filesystem"}
		}
		ev.LoadModule.File.Filesystem = rv
		return nil
	case "load_module.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.GID"}
		}
		ev.LoadModule.File.FileFields.GID = uint32(rv)
		return nil
	case "load_module.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.Group"}
		}
		ev.LoadModule.File.FileFields.Group = rv
		return nil
	case "load_module.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.InUpperLayer"}
		}
		ev.LoadModule.File.FileFields.InUpperLayer = rv
		return nil
	case "load_module.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.PathKey.Inode"}
		}
		ev.LoadModule.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "load_module.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.Mode"}
		}
		ev.LoadModule.File.FileFields.Mode = uint16(rv)
		return nil
	case "load_module.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.MTime"}
		}
		ev.LoadModule.File.FileFields.MTime = uint64(rv)
		return nil
	case "load_module.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.PathKey.MountID"}
		}
		ev.LoadModule.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "load_module.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.BasenameStr"}
		}
		ev.LoadModule.File.BasenameStr = rv
		return nil
	case "load_module.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "load_module.file.name.length"}
	case "load_module.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.PkgName"}
		}
		ev.LoadModule.File.PkgName = rv
		return nil
	case "load_module.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.PkgSrcVersion"}
		}
		ev.LoadModule.File.PkgSrcVersion = rv
		return nil
	case "load_module.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.PkgVersion"}
		}
		ev.LoadModule.File.PkgVersion = rv
		return nil
	case "load_module.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.PathnameStr"}
		}
		ev.LoadModule.File.PathnameStr = rv
		return nil
	case "load_module.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "load_module.file.path.length"}
	case "load_module.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.Mode"}
		}
		ev.LoadModule.File.FileFields.Mode = uint16(rv)
		return nil
	case "load_module.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.UID"}
		}
		ev.LoadModule.File.FileFields.UID = uint32(rv)
		return nil
	case "load_module.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.File.FileFields.User"}
		}
		ev.LoadModule.File.FileFields.User = rv
		return nil
	case "load_module.loaded_from_memory":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.LoadedFromMemory"}
		}
		ev.LoadModule.LoadedFromMemory = rv
		return nil
	case "load_module.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.Name"}
		}
		ev.LoadModule.Name = rv
		return nil
	case "load_module.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "LoadModule.SyscallEvent.Retval"}
		}
		ev.LoadModule.SyscallEvent.Retval = int64(rv)
		return nil
	case "mkdir.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.CTime"}
		}
		ev.Mkdir.File.FileFields.CTime = uint64(rv)
		return nil
	case "mkdir.file.destination.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.Mode"}
		}
		ev.Mkdir.Mode = uint32(rv)
		return nil
	case "mkdir.file.destination.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.Mode"}
		}
		ev.Mkdir.Mode = uint32(rv)
		return nil
	case "mkdir.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.Filesystem"}
		}
		ev.Mkdir.File.Filesystem = rv
		return nil
	case "mkdir.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.GID"}
		}
		ev.Mkdir.File.FileFields.GID = uint32(rv)
		return nil
	case "mkdir.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Group"}
		}
		ev.Mkdir.File.FileFields.Group = rv
		return nil
	case "mkdir.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.InUpperLayer"}
		}
		ev.Mkdir.File.FileFields.InUpperLayer = rv
		return nil
	case "mkdir.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.PathKey.Inode"}
		}
		ev.Mkdir.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "mkdir.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Mode"}
		}
		ev.Mkdir.File.FileFields.Mode = uint16(rv)
		return nil
	case "mkdir.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.MTime"}
		}
		ev.Mkdir.File.FileFields.MTime = uint64(rv)
		return nil
	case "mkdir.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.PathKey.MountID"}
		}
		ev.Mkdir.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "mkdir.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.BasenameStr"}
		}
		ev.Mkdir.File.BasenameStr = rv
		return nil
	case "mkdir.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "mkdir.file.name.length"}
	case "mkdir.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.PkgName"}
		}
		ev.Mkdir.File.PkgName = rv
		return nil
	case "mkdir.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.PkgSrcVersion"}
		}
		ev.Mkdir.File.PkgSrcVersion = rv
		return nil
	case "mkdir.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.PkgVersion"}
		}
		ev.Mkdir.File.PkgVersion = rv
		return nil
	case "mkdir.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.PathnameStr"}
		}
		ev.Mkdir.File.PathnameStr = rv
		return nil
	case "mkdir.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "mkdir.file.path.length"}
	case "mkdir.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.Mode"}
		}
		ev.Mkdir.File.FileFields.Mode = uint16(rv)
		return nil
	case "mkdir.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.UID"}
		}
		ev.Mkdir.File.FileFields.UID = uint32(rv)
		return nil
	case "mkdir.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.File.FileFields.User"}
		}
		ev.Mkdir.File.FileFields.User = rv
		return nil
	case "mkdir.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mkdir.SyscallEvent.Retval"}
		}
		ev.Mkdir.SyscallEvent.Retval = int64(rv)
		return nil
	case "mmap.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.CTime"}
		}
		ev.MMap.File.FileFields.CTime = uint64(rv)
		return nil
	case "mmap.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.Filesystem"}
		}
		ev.MMap.File.Filesystem = rv
		return nil
	case "mmap.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.GID"}
		}
		ev.MMap.File.FileFields.GID = uint32(rv)
		return nil
	case "mmap.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.Group"}
		}
		ev.MMap.File.FileFields.Group = rv
		return nil
	case "mmap.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.InUpperLayer"}
		}
		ev.MMap.File.FileFields.InUpperLayer = rv
		return nil
	case "mmap.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.PathKey.Inode"}
		}
		ev.MMap.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "mmap.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.Mode"}
		}
		ev.MMap.File.FileFields.Mode = uint16(rv)
		return nil
	case "mmap.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.MTime"}
		}
		ev.MMap.File.FileFields.MTime = uint64(rv)
		return nil
	case "mmap.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.PathKey.MountID"}
		}
		ev.MMap.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "mmap.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.BasenameStr"}
		}
		ev.MMap.File.BasenameStr = rv
		return nil
	case "mmap.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "mmap.file.name.length"}
	case "mmap.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.PkgName"}
		}
		ev.MMap.File.PkgName = rv
		return nil
	case "mmap.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.PkgSrcVersion"}
		}
		ev.MMap.File.PkgSrcVersion = rv
		return nil
	case "mmap.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.PkgVersion"}
		}
		ev.MMap.File.PkgVersion = rv
		return nil
	case "mmap.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.PathnameStr"}
		}
		ev.MMap.File.PathnameStr = rv
		return nil
	case "mmap.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "mmap.file.path.length"}
	case "mmap.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.Mode"}
		}
		ev.MMap.File.FileFields.Mode = uint16(rv)
		return nil
	case "mmap.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.UID"}
		}
		ev.MMap.File.FileFields.UID = uint32(rv)
		return nil
	case "mmap.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.File.FileFields.User"}
		}
		ev.MMap.File.FileFields.User = rv
		return nil
	case "mmap.flags":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.Flags"}
		}
		ev.MMap.Flags = int(rv)
		return nil
	case "mmap.protection":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.Protection"}
		}
		ev.MMap.Protection = int(rv)
		return nil
	case "mmap.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MMap.SyscallEvent.Retval"}
		}
		ev.MMap.SyscallEvent.Retval = int64(rv)
		return nil
	case "mount.fs_type":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mount.Mount.FSType"}
		}
		ev.Mount.Mount.FSType = rv
		return nil
	case "mount.mountpoint.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mount.MountPointPath"}
		}
		ev.Mount.MountPointPath = rv
		return nil
	case "mount.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mount.SyscallEvent.Retval"}
		}
		ev.Mount.SyscallEvent.Retval = int64(rv)
		return nil
	case "mount.source.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Mount.MountSourcePath"}
		}
		ev.Mount.MountSourcePath = rv
		return nil
	case "mprotect.req_protection":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MProtect.ReqProtection"}
		}
		ev.MProtect.ReqProtection = int(rv)
		return nil
	case "mprotect.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MProtect.SyscallEvent.Retval"}
		}
		ev.MProtect.SyscallEvent.Retval = int64(rv)
		return nil
	case "mprotect.vm_protection":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "MProtect.VMProtection"}
		}
		ev.MProtect.VMProtection = int(rv)
		return nil
	case "open.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.CTime"}
		}
		ev.Open.File.FileFields.CTime = uint64(rv)
		return nil
	case "open.file.destination.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.Mode"}
		}
		ev.Open.Mode = uint32(rv)
		return nil
	case "open.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.Filesystem"}
		}
		ev.Open.File.Filesystem = rv
		return nil
	case "open.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.GID"}
		}
		ev.Open.File.FileFields.GID = uint32(rv)
		return nil
	case "open.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Group"}
		}
		ev.Open.File.FileFields.Group = rv
		return nil
	case "open.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.InUpperLayer"}
		}
		ev.Open.File.FileFields.InUpperLayer = rv
		return nil
	case "open.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.PathKey.Inode"}
		}
		ev.Open.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "open.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Mode"}
		}
		ev.Open.File.FileFields.Mode = uint16(rv)
		return nil
	case "open.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.MTime"}
		}
		ev.Open.File.FileFields.MTime = uint64(rv)
		return nil
	case "open.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.PathKey.MountID"}
		}
		ev.Open.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "open.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.BasenameStr"}
		}
		ev.Open.File.BasenameStr = rv
		return nil
	case "open.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "open.file.name.length"}
	case "open.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.PkgName"}
		}
		ev.Open.File.PkgName = rv
		return nil
	case "open.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.PkgSrcVersion"}
		}
		ev.Open.File.PkgSrcVersion = rv
		return nil
	case "open.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.PkgVersion"}
		}
		ev.Open.File.PkgVersion = rv
		return nil
	case "open.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.PathnameStr"}
		}
		ev.Open.File.PathnameStr = rv
		return nil
	case "open.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "open.file.path.length"}
	case "open.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.Mode"}
		}
		ev.Open.File.FileFields.Mode = uint16(rv)
		return nil
	case "open.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.UID"}
		}
		ev.Open.File.FileFields.UID = uint32(rv)
		return nil
	case "open.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.File.FileFields.User"}
		}
		ev.Open.File.FileFields.User = rv
		return nil
	case "open.flags":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.Flags"}
		}
		ev.Open.Flags = uint32(rv)
		return nil
	case "open.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Open.SyscallEvent.Retval"}
		}
		ev.Open.SyscallEvent.Retval = int64(rv)
		return nil
	case "ptrace.request":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "PTrace.Request"}
		}
		ev.PTrace.Request = uint32(rv)
		return nil
	case "ptrace.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "PTrace.SyscallEvent.Retval"}
		}
		ev.PTrace.SyscallEvent.Retval = int64(rv)
		return nil
	case "removexattr.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.CTime"}
		}
		ev.RemoveXAttr.File.FileFields.CTime = uint64(rv)
		return nil
	case "removexattr.file.destination.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.Name"}
		}
		ev.RemoveXAttr.Name = rv
		return nil
	case "removexattr.file.destination.namespace":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.Namespace"}
		}
		ev.RemoveXAttr.Namespace = rv
		return nil
	case "removexattr.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.Filesystem"}
		}
		ev.RemoveXAttr.File.Filesystem = rv
		return nil
	case "removexattr.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.GID"}
		}
		ev.RemoveXAttr.File.FileFields.GID = uint32(rv)
		return nil
	case "removexattr.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Group"}
		}
		ev.RemoveXAttr.File.FileFields.Group = rv
		return nil
	case "removexattr.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.InUpperLayer"}
		}
		ev.RemoveXAttr.File.FileFields.InUpperLayer = rv
		return nil
	case "removexattr.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.PathKey.Inode"}
		}
		ev.RemoveXAttr.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "removexattr.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Mode"}
		}
		ev.RemoveXAttr.File.FileFields.Mode = uint16(rv)
		return nil
	case "removexattr.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.MTime"}
		}
		ev.RemoveXAttr.File.FileFields.MTime = uint64(rv)
		return nil
	case "removexattr.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.PathKey.MountID"}
		}
		ev.RemoveXAttr.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "removexattr.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.BasenameStr"}
		}
		ev.RemoveXAttr.File.BasenameStr = rv
		return nil
	case "removexattr.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "removexattr.file.name.length"}
	case "removexattr.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.PkgName"}
		}
		ev.RemoveXAttr.File.PkgName = rv
		return nil
	case "removexattr.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.PkgSrcVersion"}
		}
		ev.RemoveXAttr.File.PkgSrcVersion = rv
		return nil
	case "removexattr.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.PkgVersion"}
		}
		ev.RemoveXAttr.File.PkgVersion = rv
		return nil
	case "removexattr.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.PathnameStr"}
		}
		ev.RemoveXAttr.File.PathnameStr = rv
		return nil
	case "removexattr.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "removexattr.file.path.length"}
	case "removexattr.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.Mode"}
		}
		ev.RemoveXAttr.File.FileFields.Mode = uint16(rv)
		return nil
	case "removexattr.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.UID"}
		}
		ev.RemoveXAttr.File.FileFields.UID = uint32(rv)
		return nil
	case "removexattr.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.File.FileFields.User"}
		}
		ev.RemoveXAttr.File.FileFields.User = rv
		return nil
	case "removexattr.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "RemoveXAttr.SyscallEvent.Retval"}
		}
		ev.RemoveXAttr.SyscallEvent.Retval = int64(rv)
		return nil
	case "rename.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.CTime"}
		}
		ev.Rename.Old.FileFields.CTime = uint64(rv)
		return nil
	case "rename.file.destination.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.CTime"}
		}
		ev.Rename.New.FileFields.CTime = uint64(rv)
		return nil
	case "rename.file.destination.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.Filesystem"}
		}
		ev.Rename.New.Filesystem = rv
		return nil
	case "rename.file.destination.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.GID"}
		}
		ev.Rename.New.FileFields.GID = uint32(rv)
		return nil
	case "rename.file.destination.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Group"}
		}
		ev.Rename.New.FileFields.Group = rv
		return nil
	case "rename.file.destination.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.InUpperLayer"}
		}
		ev.Rename.New.FileFields.InUpperLayer = rv
		return nil
	case "rename.file.destination.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.PathKey.Inode"}
		}
		ev.Rename.New.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "rename.file.destination.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Mode"}
		}
		ev.Rename.New.FileFields.Mode = uint16(rv)
		return nil
	case "rename.file.destination.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.MTime"}
		}
		ev.Rename.New.FileFields.MTime = uint64(rv)
		return nil
	case "rename.file.destination.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.PathKey.MountID"}
		}
		ev.Rename.New.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "rename.file.destination.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.BasenameStr"}
		}
		ev.Rename.New.BasenameStr = rv
		return nil
	case "rename.file.destination.name.length":
		return &eval.ErrFieldReadOnly{Field: "rename.file.destination.name.length"}
	case "rename.file.destination.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.PkgName"}
		}
		ev.Rename.New.PkgName = rv
		return nil
	case "rename.file.destination.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.PkgSrcVersion"}
		}
		ev.Rename.New.PkgSrcVersion = rv
		return nil
	case "rename.file.destination.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.PkgVersion"}
		}
		ev.Rename.New.PkgVersion = rv
		return nil
	case "rename.file.destination.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.PathnameStr"}
		}
		ev.Rename.New.PathnameStr = rv
		return nil
	case "rename.file.destination.path.length":
		return &eval.ErrFieldReadOnly{Field: "rename.file.destination.path.length"}
	case "rename.file.destination.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.Mode"}
		}
		ev.Rename.New.FileFields.Mode = uint16(rv)
		return nil
	case "rename.file.destination.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.UID"}
		}
		ev.Rename.New.FileFields.UID = uint32(rv)
		return nil
	case "rename.file.destination.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.New.FileFields.User"}
		}
		ev.Rename.New.FileFields.User = rv
		return nil
	case "rename.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.Filesystem"}
		}
		ev.Rename.Old.Filesystem = rv
		return nil
	case "rename.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.GID"}
		}
		ev.Rename.Old.FileFields.GID = uint32(rv)
		return nil
	case "rename.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Group"}
		}
		ev.Rename.Old.FileFields.Group = rv
		return nil
	case "rename.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.InUpperLayer"}
		}
		ev.Rename.Old.FileFields.InUpperLayer = rv
		return nil
	case "rename.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.PathKey.Inode"}
		}
		ev.Rename.Old.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "rename.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Mode"}
		}
		ev.Rename.Old.FileFields.Mode = uint16(rv)
		return nil
	case "rename.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.MTime"}
		}
		ev.Rename.Old.FileFields.MTime = uint64(rv)
		return nil
	case "rename.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.PathKey.MountID"}
		}
		ev.Rename.Old.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "rename.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.BasenameStr"}
		}
		ev.Rename.Old.BasenameStr = rv
		return nil
	case "rename.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "rename.file.name.length"}
	case "rename.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.PkgName"}
		}
		ev.Rename.Old.PkgName = rv
		return nil
	case "rename.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.PkgSrcVersion"}
		}
		ev.Rename.Old.PkgSrcVersion = rv
		return nil
	case "rename.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.PkgVersion"}
		}
		ev.Rename.Old.PkgVersion = rv
		return nil
	case "rename.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.PathnameStr"}
		}
		ev.Rename.Old.PathnameStr = rv
		return nil
	case "rename.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "rename.file.path.length"}
	case "rename.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.Mode"}
		}
		ev.Rename.Old.FileFields.Mode = uint16(rv)
		return nil
	case "rename.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.UID"}
		}
		ev.Rename.Old.FileFields.UID = uint32(rv)
		return nil
	case "rename.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.Old.FileFields.User"}
		}
		ev.Rename.Old.FileFields.User = rv
		return nil
	case "rename.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rename.SyscallEvent.Retval"}
		}
		ev.Rename.SyscallEvent.Retval = int64(rv)
		return nil
	case "rmdir.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.CTime"}
		}
		ev.Rmdir.File.FileFields.CTime = uint64(rv)
		return nil
	case "rmdir.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.Filesystem"}
		}
		ev.Rmdir.File.Filesystem = rv
		return nil
	case "rmdir.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.GID"}
		}
		ev.Rmdir.File.FileFields.GID = uint32(rv)
		return nil
	case "rmdir.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Group"}
		}
		ev.Rmdir.File.FileFields.Group = rv
		return nil
	case "rmdir.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.InUpperLayer"}
		}
		ev.Rmdir.File.FileFields.InUpperLayer = rv
		return nil
	case "rmdir.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.PathKey.Inode"}
		}
		ev.Rmdir.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "rmdir.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Mode"}
		}
		ev.Rmdir.File.FileFields.Mode = uint16(rv)
		return nil
	case "rmdir.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.MTime"}
		}
		ev.Rmdir.File.FileFields.MTime = uint64(rv)
		return nil
	case "rmdir.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.PathKey.MountID"}
		}
		ev.Rmdir.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "rmdir.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.BasenameStr"}
		}
		ev.Rmdir.File.BasenameStr = rv
		return nil
	case "rmdir.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "rmdir.file.name.length"}
	case "rmdir.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.PkgName"}
		}
		ev.Rmdir.File.PkgName = rv
		return nil
	case "rmdir.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.PkgSrcVersion"}
		}
		ev.Rmdir.File.PkgSrcVersion = rv
		return nil
	case "rmdir.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.PkgVersion"}
		}
		ev.Rmdir.File.PkgVersion = rv
		return nil
	case "rmdir.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.PathnameStr"}
		}
		ev.Rmdir.File.PathnameStr = rv
		return nil
	case "rmdir.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "rmdir.file.path.length"}
	case "rmdir.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.Mode"}
		}
		ev.Rmdir.File.FileFields.Mode = uint16(rv)
		return nil
	case "rmdir.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.UID"}
		}
		ev.Rmdir.File.FileFields.UID = uint32(rv)
		return nil
	case "rmdir.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.File.FileFields.User"}
		}
		ev.Rmdir.File.FileFields.User = rv
		return nil
	case "rmdir.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Rmdir.SyscallEvent.Retval"}
		}
		ev.Rmdir.SyscallEvent.Retval = int64(rv)
		return nil
	case "selinux.bool.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SELinux.BoolName"}
		}
		ev.SELinux.BoolName = rv
		return nil
	case "selinux.bool.state":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SELinux.BoolChangeValue"}
		}
		ev.SELinux.BoolChangeValue = rv
		return nil
	case "selinux.bool_commit.state":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SELinux.BoolCommitValue"}
		}
		ev.SELinux.BoolCommitValue = rv
		return nil
	case "selinux.enforce.status":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SELinux.EnforceStatus"}
		}
		ev.SELinux.EnforceStatus = rv
		return nil
	case "setgid.egid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.EGID"}
		}
		ev.SetGID.EGID = uint32(rv)
		return nil
	case "setgid.egroup":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.EGroup"}
		}
		ev.SetGID.EGroup = rv
		return nil
	case "setgid.fsgid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.FSGID"}
		}
		ev.SetGID.FSGID = uint32(rv)
		return nil
	case "setgid.fsgroup":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.FSGroup"}
		}
		ev.SetGID.FSGroup = rv
		return nil
	case "setgid.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.GID"}
		}
		ev.SetGID.GID = uint32(rv)
		return nil
	case "setgid.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetGID.Group"}
		}
		ev.SetGID.Group = rv
		return nil
	case "setuid.euid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.EUID"}
		}
		ev.SetUID.EUID = uint32(rv)
		return nil
	case "setuid.euser":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.EUser"}
		}
		ev.SetUID.EUser = rv
		return nil
	case "setuid.fsuid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.FSUID"}
		}
		ev.SetUID.FSUID = uint32(rv)
		return nil
	case "setuid.fsuser":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.FSUser"}
		}
		ev.SetUID.FSUser = rv
		return nil
	case "setuid.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.UID"}
		}
		ev.SetUID.UID = uint32(rv)
		return nil
	case "setuid.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetUID.User"}
		}
		ev.SetUID.User = rv
		return nil
	case "setxattr.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.CTime"}
		}
		ev.SetXAttr.File.FileFields.CTime = uint64(rv)
		return nil
	case "setxattr.file.destination.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.Name"}
		}
		ev.SetXAttr.Name = rv
		return nil
	case "setxattr.file.destination.namespace":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.Namespace"}
		}
		ev.SetXAttr.Namespace = rv
		return nil
	case "setxattr.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.Filesystem"}
		}
		ev.SetXAttr.File.Filesystem = rv
		return nil
	case "setxattr.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.GID"}
		}
		ev.SetXAttr.File.FileFields.GID = uint32(rv)
		return nil
	case "setxattr.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Group"}
		}
		ev.SetXAttr.File.FileFields.Group = rv
		return nil
	case "setxattr.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.InUpperLayer"}
		}
		ev.SetXAttr.File.FileFields.InUpperLayer = rv
		return nil
	case "setxattr.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.PathKey.Inode"}
		}
		ev.SetXAttr.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "setxattr.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Mode"}
		}
		ev.SetXAttr.File.FileFields.Mode = uint16(rv)
		return nil
	case "setxattr.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.MTime"}
		}
		ev.SetXAttr.File.FileFields.MTime = uint64(rv)
		return nil
	case "setxattr.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.PathKey.MountID"}
		}
		ev.SetXAttr.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "setxattr.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.BasenameStr"}
		}
		ev.SetXAttr.File.BasenameStr = rv
		return nil
	case "setxattr.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "setxattr.file.name.length"}
	case "setxattr.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.PkgName"}
		}
		ev.SetXAttr.File.PkgName = rv
		return nil
	case "setxattr.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.PkgSrcVersion"}
		}
		ev.SetXAttr.File.PkgSrcVersion = rv
		return nil
	case "setxattr.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.PkgVersion"}
		}
		ev.SetXAttr.File.PkgVersion = rv
		return nil
	case "setxattr.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.PathnameStr"}
		}
		ev.SetXAttr.File.PathnameStr = rv
		return nil
	case "setxattr.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "setxattr.file.path.length"}
	case "setxattr.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.Mode"}
		}
		ev.SetXAttr.File.FileFields.Mode = uint16(rv)
		return nil
	case "setxattr.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.UID"}
		}
		ev.SetXAttr.File.FileFields.UID = uint32(rv)
		return nil
	case "setxattr.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.File.FileFields.User"}
		}
		ev.SetXAttr.File.FileFields.User = rv
		return nil
	case "setxattr.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "SetXAttr.SyscallEvent.Retval"}
		}
		ev.SetXAttr.SyscallEvent.Retval = int64(rv)
		return nil
	case "signal.pid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Signal.PID"}
		}
		ev.Signal.PID = uint32(rv)
		return nil
	case "signal.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Signal.SyscallEvent.Retval"}
		}
		ev.Signal.SyscallEvent.Retval = int64(rv)
		return nil
	case "signal.type":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Signal.Type"}
		}
		ev.Signal.Type = uint32(rv)
		return nil
	case "splice.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.CTime"}
		}
		ev.Splice.File.FileFields.CTime = uint64(rv)
		return nil
	case "splice.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.Filesystem"}
		}
		ev.Splice.File.Filesystem = rv
		return nil
	case "splice.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.GID"}
		}
		ev.Splice.File.FileFields.GID = uint32(rv)
		return nil
	case "splice.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.Group"}
		}
		ev.Splice.File.FileFields.Group = rv
		return nil
	case "splice.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.InUpperLayer"}
		}
		ev.Splice.File.FileFields.InUpperLayer = rv
		return nil
	case "splice.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.PathKey.Inode"}
		}
		ev.Splice.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "splice.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.Mode"}
		}
		ev.Splice.File.FileFields.Mode = uint16(rv)
		return nil
	case "splice.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.MTime"}
		}
		ev.Splice.File.FileFields.MTime = uint64(rv)
		return nil
	case "splice.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.PathKey.MountID"}
		}
		ev.Splice.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "splice.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.BasenameStr"}
		}
		ev.Splice.File.BasenameStr = rv
		return nil
	case "splice.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "splice.file.name.length"}
	case "splice.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.PkgName"}
		}
		ev.Splice.File.PkgName = rv
		return nil
	case "splice.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.PkgSrcVersion"}
		}
		ev.Splice.File.PkgSrcVersion = rv
		return nil
	case "splice.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.PkgVersion"}
		}
		ev.Splice.File.PkgVersion = rv
		return nil
	case "splice.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.PathnameStr"}
		}
		ev.Splice.File.PathnameStr = rv
		return nil
	case "splice.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "splice.file.path.length"}
	case "splice.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.Mode"}
		}
		ev.Splice.File.FileFields.Mode = uint16(rv)
		return nil
	case "splice.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.UID"}
		}
		ev.Splice.File.FileFields.UID = uint32(rv)
		return nil
	case "splice.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.File.FileFields.User"}
		}
		ev.Splice.File.FileFields.User = rv
		return nil
	case "splice.pipe_entry_flag":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.PipeEntryFlag"}
		}
		ev.Splice.PipeEntryFlag = uint32(rv)
		return nil
	case "splice.pipe_exit_flag":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.PipeExitFlag"}
		}
		ev.Splice.PipeExitFlag = uint32(rv)
		return nil
	case "splice.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Splice.SyscallEvent.Retval"}
		}
		ev.Splice.SyscallEvent.Retval = int64(rv)
		return nil
	case "unlink.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.CTime"}
		}
		ev.Unlink.File.FileFields.CTime = uint64(rv)
		return nil
	case "unlink.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.Filesystem"}
		}
		ev.Unlink.File.Filesystem = rv
		return nil
	case "unlink.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.GID"}
		}
		ev.Unlink.File.FileFields.GID = uint32(rv)
		return nil
	case "unlink.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Group"}
		}
		ev.Unlink.File.FileFields.Group = rv
		return nil
	case "unlink.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.InUpperLayer"}
		}
		ev.Unlink.File.FileFields.InUpperLayer = rv
		return nil
	case "unlink.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.PathKey.Inode"}
		}
		ev.Unlink.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "unlink.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Mode"}
		}
		ev.Unlink.File.FileFields.Mode = uint16(rv)
		return nil
	case "unlink.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.MTime"}
		}
		ev.Unlink.File.FileFields.MTime = uint64(rv)
		return nil
	case "unlink.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.PathKey.MountID"}
		}
		ev.Unlink.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "unlink.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.BasenameStr"}
		}
		ev.Unlink.File.BasenameStr = rv
		return nil
	case "unlink.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "unlink.file.name.length"}
	case "unlink.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.PkgName"}
		}
		ev.Unlink.File.PkgName = rv
		return nil
	case "unlink.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.PkgSrcVersion"}
		}
		ev.Unlink.File.PkgSrcVersion = rv
		return nil
	case "unlink.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.PkgVersion"}
		}
		ev.Unlink.File.PkgVersion = rv
		return nil
	case "unlink.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.PathnameStr"}
		}
		ev.Unlink.File.PathnameStr = rv
		return nil
	case "unlink.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "unlink.file.path.length"}
	case "unlink.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.Mode"}
		}
		ev.Unlink.File.FileFields.Mode = uint16(rv)
		return nil
	case "unlink.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.UID"}
		}
		ev.Unlink.File.FileFields.UID = uint32(rv)
		return nil
	case "unlink.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.File.FileFields.User"}
		}
		ev.Unlink.File.FileFields.User = rv
		return nil
	case "unlink.flags":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.Flags"}
		}
		ev.Unlink.Flags = uint32(rv)
		return nil
	case "unlink.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Unlink.SyscallEvent.Retval"}
		}
		ev.Unlink.SyscallEvent.Retval = int64(rv)
		return nil
	case "unload_module.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "UnloadModule.Name"}
		}
		ev.UnloadModule.Name = rv
		return nil
	case "unload_module.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "UnloadModule.SyscallEvent.Retval"}
		}
		ev.UnloadModule.SyscallEvent.Retval = int64(rv)
		return nil
	case "utimes.file.change_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.CTime"}
		}
		ev.Utimes.File.FileFields.CTime = uint64(rv)
		return nil
	case "utimes.file.filesystem":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.Filesystem"}
		}
		ev.Utimes.File.Filesystem = rv
		return nil
	case "utimes.file.gid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.GID"}
		}
		ev.Utimes.File.FileFields.GID = uint32(rv)
		return nil
	case "utimes.file.group":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Group"}
		}
		ev.Utimes.File.FileFields.Group = rv
		return nil
	case "utimes.file.in_upper_layer":
		rv, ok := value.(bool)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.InUpperLayer"}
		}
		ev.Utimes.File.FileFields.InUpperLayer = rv
		return nil
	case "utimes.file.inode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.PathKey.Inode"}
		}
		ev.Utimes.File.FileFields.PathKey.Inode = uint64(rv)
		return nil
	case "utimes.file.mode":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Mode"}
		}
		ev.Utimes.File.FileFields.Mode = uint16(rv)
		return nil
	case "utimes.file.modification_time":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.MTime"}
		}
		ev.Utimes.File.FileFields.MTime = uint64(rv)
		return nil
	case "utimes.file.mount_id":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.PathKey.MountID"}
		}
		ev.Utimes.File.FileFields.PathKey.MountID = uint32(rv)
		return nil
	case "utimes.file.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.BasenameStr"}
		}
		ev.Utimes.File.BasenameStr = rv
		return nil
	case "utimes.file.name.length":
		return &eval.ErrFieldReadOnly{Field: "utimes.file.name.length"}
	case "utimes.file.package.name":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.PkgName"}
		}
		ev.Utimes.File.PkgName = rv
		return nil
	case "utimes.file.package.source_version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.PkgSrcVersion"}
		}
		ev.Utimes.File.PkgSrcVersion = rv
		return nil
	case "utimes.file.package.version":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.PkgVersion"}
		}
		ev.Utimes.File.PkgVersion = rv
		return nil
	case "utimes.file.path":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.PathnameStr"}
		}
		ev.Utimes.File.PathnameStr = rv
		return nil
	case "utimes.file.path.length":
		return &eval.ErrFieldReadOnly{Field: "utimes.file.path.length"}
	case "utimes.file.rights":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.Mode"}
		}
		ev.Utimes.File.FileFields.Mode = uint16(rv)
		return nil
	case "utimes.file.uid":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.UID"}
		}
		ev.Utimes.File.FileFields.UID = uint32(rv)
		return nil
	case "utimes.file.user":
		rv, ok := value.(string)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.File.FileFields.User"}
		}
		ev.Utimes.File.FileFields.User = rv
		return nil
	case "utimes.retval":
		rv, ok := value.(int)
		if !ok {
			return &eval.ErrValueTypeMismatch{Field: "Utimes.SyscallEvent.Retval"}
		}
		ev.Utimes.SyscallEvent.Retval = int64(rv)
		return nil
	}
	return &eval.ErrFieldNotFound{Field: field}
}
