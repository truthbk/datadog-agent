// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:generate go run github.com/DataDog/datadog-agent/pkg/security/secl/compiler/generators/accessors -tags windows -output accessors_windows.go -field-handlers-tags windows -field-handlers field_handlers_windows.go -doc ../../../../docs/cloud-workload-security/secl-windows.json

package model

// Event represents an event sent from the kernel
// genaccessors
type Event struct {
	CommonFields
}
