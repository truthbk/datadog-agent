// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package windows

// TODO: we can't import the windows package on linux. how can we get constants?
const (
	SERVICE_AUTO_START   = 2
	SERVICE_DEMAND_START = 3
	SERVICE_DISABLED     = 4

	SERVICE_STOPPED = 1
	SERVICE_RUNNING = 4
)
