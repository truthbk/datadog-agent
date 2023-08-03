// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package state

// AgentTaskConfig is a deserialized agent task configuration file
// along with the associated metadata
type AgentTaskConfig struct {
	Config   AgentTaskData
	Metadata Metadata
}

// AgentTaskData is the content of a agent task configuration file
type AgentTaskData struct {
	TaskType string            `json:"task_type"`
	UUID     string            `json:"uuid"`
	TaskArgs map[string]string `json:"args"`
}
