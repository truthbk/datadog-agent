// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package common

import corev1 "k8s.io/api/core/v1"

type LibConfig struct {
	TraceSampleRate string `json:"trace_sample_rate,omitempty"`
}

func (lc LibConfig) ToEnvs() []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name:  "DD_TRACE_SAMPLE_RATE",
			Value: lc.TraceSampleRate,
		},
	}
}
