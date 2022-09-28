// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package internal

// BundleParams defines the parameters for this bundle.
type BundleParams struct {
	// PidFilePat is the path to the agent's pid file.  If this is empty, then no
	// pid file is written.
	PidfilePath string

	// SysProbeConfFilePath holds the path to the folder containing the system-probe
	// configuration file, to allow overrides from the command line.
	SysProbeConfFilePath string
}
