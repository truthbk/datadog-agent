// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.

//go:build windows
// +build windows

package model

type FieldHandlers interface {
	ResolveEventTimestamp(ev *Event) int
	// custom handlers not tied to any fields
	ExtraFieldHandlers
}
type DefaultFieldHandlers struct{}

func (dfh *DefaultFieldHandlers) ResolveEventTimestamp(ev *Event) int { return int(ev.TimestampRaw) }
