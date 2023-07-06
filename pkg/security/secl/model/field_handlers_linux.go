// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.

//go:build linux
// +build linux

package model

// ResolveFields resolves all the fields associate to the event type. Context fields are automatically resolved.
func (ev *Event) ResolveFields() {
	ev.resolveFields(false)
}

// ResolveFieldsForAD resolves all the fields associate to the event type. Context fields are automatically resolved.
func (ev *Event) ResolveFieldsForAD() {
	ev.resolveFields(true)
}
func (ev *Event) resolveFields(forADs bool) {
	// resolve context fields that are not related to any event type
	_ = ev.FieldHandlers.ResolveAsync(ev)
}

type FieldHandlers interface {
	ResolveAsync(ev *Event) bool
	ResolveChownGID(ev *Event, e *ChownEvent) string
	ResolveChownUID(ev *Event, e *ChownEvent) string
	ResolveEventTimestamp(ev *Event, e *CommonFields) int
	ResolveFileBasename(ev *Event, e *FileEvent) string
	ResolveFileFieldsGroup(ev *Event, e *FileFields) string
	ResolveFileFieldsInUpperLayer(ev *Event, e *FileFields) bool
	ResolveFileFieldsUser(ev *Event, e *FileFields) string
	ResolveFileFilesystem(ev *Event, e *FileEvent) string
	ResolveFilePath(ev *Event, e *FileEvent) string
	ResolveModuleArgs(ev *Event, e *LoadModuleEvent) string
	ResolveModuleArgv(ev *Event, e *LoadModuleEvent) []string
	ResolveMountPointPath(ev *Event, e *MountEvent) string
	ResolveMountSourcePath(ev *Event, e *MountEvent) string
	ResolvePackageName(ev *Event, e *FileEvent) string
	ResolvePackageSourceVersion(ev *Event, e *FileEvent) string
	ResolvePackageVersion(ev *Event, e *FileEvent) string
	ResolveProcessArgs(ev *Event, e *Process) string
	ResolveProcessArgsFlags(ev *Event, e *Process) []string
	ResolveProcessArgsOptions(ev *Event, e *Process) []string
	ResolveProcessArgsTruncated(ev *Event, e *Process) bool
	ResolveProcessArgv(ev *Event, e *Process) []string
	ResolveProcessArgv0(ev *Event, e *Process) string
	ResolveProcessCreatedAt(ev *Event, e *Process) int
	ResolveProcessEnvp(ev *Event, e *Process) []string
	ResolveProcessEnvs(ev *Event, e *Process) []string
	ResolveProcessEnvsTruncated(ev *Event, e *Process) bool
	ResolveRights(ev *Event, e *FileFields) int
	ResolveSELinuxBoolName(ev *Event, e *SELinuxEvent) string
	ResolveSetgidEGroup(ev *Event, e *SetgidEvent) string
	ResolveSetgidFSGroup(ev *Event, e *SetgidEvent) string
	ResolveSetgidGroup(ev *Event, e *SetgidEvent) string
	ResolveSetuidEUser(ev *Event, e *SetuidEvent) string
	ResolveSetuidFSUser(ev *Event, e *SetuidEvent) string
	ResolveSetuidUser(ev *Event, e *SetuidEvent) string
	ResolveXAttrName(ev *Event, e *SetXAttrEvent) string
	ResolveXAttrNamespace(ev *Event, e *SetXAttrEvent) string
	// custom handlers not tied to any fields
	ExtraFieldHandlers
}
type DefaultFieldHandlers struct{}

func (dfh *DefaultFieldHandlers) ResolveAsync(ev *Event) bool                     { return ev.Async }
func (dfh *DefaultFieldHandlers) ResolveChownGID(ev *Event, e *ChownEvent) string { return e.Group }
func (dfh *DefaultFieldHandlers) ResolveChownUID(ev *Event, e *ChownEvent) string { return e.User }
func (dfh *DefaultFieldHandlers) ResolveEventTimestamp(ev *Event, e *CommonFields) int {
	return int(e.TimestampRaw)
}
func (dfh *DefaultFieldHandlers) ResolveFileBasename(ev *Event, e *FileEvent) string {
	return e.BasenameStr
}
func (dfh *DefaultFieldHandlers) ResolveFileFieldsGroup(ev *Event, e *FileFields) string {
	return e.Group
}
func (dfh *DefaultFieldHandlers) ResolveFileFieldsInUpperLayer(ev *Event, e *FileFields) bool {
	return e.InUpperLayer
}
func (dfh *DefaultFieldHandlers) ResolveFileFieldsUser(ev *Event, e *FileFields) string {
	return e.User
}
func (dfh *DefaultFieldHandlers) ResolveFileFilesystem(ev *Event, e *FileEvent) string {
	return e.Filesystem
}
func (dfh *DefaultFieldHandlers) ResolveFilePath(ev *Event, e *FileEvent) string {
	return e.PathnameStr
}
func (dfh *DefaultFieldHandlers) ResolveModuleArgs(ev *Event, e *LoadModuleEvent) string {
	return e.Args
}
func (dfh *DefaultFieldHandlers) ResolveModuleArgv(ev *Event, e *LoadModuleEvent) []string {
	return e.Argv
}
func (dfh *DefaultFieldHandlers) ResolveMountPointPath(ev *Event, e *MountEvent) string {
	return e.MountPointPath
}
func (dfh *DefaultFieldHandlers) ResolveMountSourcePath(ev *Event, e *MountEvent) string {
	return e.MountSourcePath
}
func (dfh *DefaultFieldHandlers) ResolvePackageName(ev *Event, e *FileEvent) string { return e.PkgName }
func (dfh *DefaultFieldHandlers) ResolvePackageSourceVersion(ev *Event, e *FileEvent) string {
	return e.PkgSrcVersion
}
func (dfh *DefaultFieldHandlers) ResolvePackageVersion(ev *Event, e *FileEvent) string {
	return e.PkgVersion
}
func (dfh *DefaultFieldHandlers) ResolveProcessArgs(ev *Event, e *Process) string { return e.Args }
func (dfh *DefaultFieldHandlers) ResolveProcessArgsFlags(ev *Event, e *Process) []string {
	return e.Argv
}
func (dfh *DefaultFieldHandlers) ResolveProcessArgsOptions(ev *Event, e *Process) []string {
	return e.Argv
}
func (dfh *DefaultFieldHandlers) ResolveProcessArgsTruncated(ev *Event, e *Process) bool {
	return e.ArgsTruncated
}
func (dfh *DefaultFieldHandlers) ResolveProcessArgv(ev *Event, e *Process) []string { return e.Argv }
func (dfh *DefaultFieldHandlers) ResolveProcessArgv0(ev *Event, e *Process) string  { return e.Argv0 }
func (dfh *DefaultFieldHandlers) ResolveProcessCreatedAt(ev *Event, e *Process) int {
	return int(e.CreatedAt)
}
func (dfh *DefaultFieldHandlers) ResolveProcessEnvp(ev *Event, e *Process) []string { return e.Envp }
func (dfh *DefaultFieldHandlers) ResolveProcessEnvs(ev *Event, e *Process) []string { return e.Envs }
func (dfh *DefaultFieldHandlers) ResolveProcessEnvsTruncated(ev *Event, e *Process) bool {
	return e.EnvsTruncated
}
func (dfh *DefaultFieldHandlers) ResolveRights(ev *Event, e *FileFields) int { return int(e.Mode) }
func (dfh *DefaultFieldHandlers) ResolveSELinuxBoolName(ev *Event, e *SELinuxEvent) string {
	return e.BoolName
}
func (dfh *DefaultFieldHandlers) ResolveSetgidEGroup(ev *Event, e *SetgidEvent) string {
	return e.EGroup
}
func (dfh *DefaultFieldHandlers) ResolveSetgidFSGroup(ev *Event, e *SetgidEvent) string {
	return e.FSGroup
}
func (dfh *DefaultFieldHandlers) ResolveSetgidGroup(ev *Event, e *SetgidEvent) string { return e.Group }
func (dfh *DefaultFieldHandlers) ResolveSetuidEUser(ev *Event, e *SetuidEvent) string { return e.EUser }
func (dfh *DefaultFieldHandlers) ResolveSetuidFSUser(ev *Event, e *SetuidEvent) string {
	return e.FSUser
}
func (dfh *DefaultFieldHandlers) ResolveSetuidUser(ev *Event, e *SetuidEvent) string  { return e.User }
func (dfh *DefaultFieldHandlers) ResolveXAttrName(ev *Event, e *SetXAttrEvent) string { return e.Name }
func (dfh *DefaultFieldHandlers) ResolveXAttrNamespace(ev *Event, e *SetXAttrEvent) string {
	return e.Namespace
}
