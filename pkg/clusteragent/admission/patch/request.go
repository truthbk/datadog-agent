// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package patch

type patchRequest struct {
	TargetCluster      string `yaml:"target_cluster"`
	TargetObjKind      string `yaml:"target_obj_kind"`
	TargetObjName      string `yaml:"target_obj_name"`
	TargetObjNamespace string `yaml:"target_obj_namespace"`
	Language           string `yaml:"language"`
	LibVersion         string `yaml:"lib_version"`
	TraceSampleRate    string `yaml:"trace_sample_rate,omitempty"`
}
