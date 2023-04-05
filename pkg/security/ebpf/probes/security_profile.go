// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probes

import manager "github.com/DataDog/ebpf-manager"

// securityProfileProbes holds the list of probes used by security profiles
var securityProfileProbes = []*manager.Probe{
	{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID:          SecurityAgentUID,
			EBPFFuncName: "kprobe_security_bprm_check",
		},
	},
}

func getSecurityProfileProbes() []*manager.Probe {
	return securityProfileProbes
}

func getSecurityProfileTailCallRoutes() []manager.TailCallRoute {
	return []manager.TailCallRoute{
		{
			ProgArrayName: "security_profile_evaluation_progs",
			Key:           SecurityProfileExecKey,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe_security_profile_exec_callback",
			},
		},
	}
}
