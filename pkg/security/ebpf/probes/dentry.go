// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package probes

import (
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
)

// getDentryResolverTailCallRoutes is the list of routes used during the dentry resolution process
func getDentryResolverTailCallRoutes(ERPCDentryResolutionEnabled, supportMmapableMaps bool, fentry bool) []manager.TailCallRoute {

	var routes []manager.TailCallRoute

	tracepointRoutes := []manager.TailCallRoute{
		// skip index 0 as it is used for the DR_NO_CALLBACK check
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           1,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dentry_resolver_entrypoint",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           2,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dentry_resolver_loop",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           3,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_open_callback",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           4,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_mkdir_callback",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           5,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_mount_callback",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           6,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_link_dst_callback",
			},
		},
		{
			ProgArrayName: "dr_tracepoint_progs",
			Key:           7,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint_dr_rename_callback",
			},
		},
	}

	if !fentry {
		kprobeRoutes := []manager.TailCallRoute{
			// skip index 0 as it is used for the DR_NO_CALLBACK check
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           1,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dentry_resolver_entrypoint",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           2,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dentry_resolver_loop",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           3,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_open_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           4,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_mkdir_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           5,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_mount_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           6,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_link_dst_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           7,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_rename_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           8,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_handle_executable_path_cb",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           9,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_handle_interpreter_path_cb",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           10,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_link_src_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           11,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_rename_src_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           12,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_security_inode_rmdir_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           13,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_selinux_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           14,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_setattr_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           15,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_setxattr_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           16,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_unlink_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           17,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_dr_unshare_mntns_stage_one_callback",
				},
			},
			{
				ProgArrayName: "dr_kprobe_progs",
				Key:           18,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "kprobe_trace_kernel_file_cb",
				},
			},
		}
		routes = append(tracepointRoutes, kprobeRoutes...)
	} else {
		fentryRoutes := []manager.TailCallRoute{
			// skip index 0 as it is used for the DR_NO_CALLBACK check
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           1,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dentry_resolver_entrypoint",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           2,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dentry_resolver_loop",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           3,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_open_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           4,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_mkdir_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           5,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_mount_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           6,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_link_dst_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           7,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_rename_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           8,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_handle_executable_path_cb",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           9,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_handle_interpreter_path_cb",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           10,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_link_src_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           11,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_rename_src_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           12,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_security_inode_rmdir_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           13,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_selinux_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           14,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_setattr_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           15,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_setxattr_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           16,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_unlink_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           17,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_dr_unshare_mntns_stage_one_callback",
				},
			},
			{
				ProgArrayName: "dr_fentry_progs",
				Key:           18,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "fentry_trace_kernel_file_cb",
				},
			},
		}
		routes = append(tracepointRoutes, fentryRoutes...)
	}

	if ERPCDentryResolutionEnabled {
		var progType string
		if !fentry {
			progType = "kprobe"
		} else {
			progType = "fentry"
		}
		progArrayName := fmt.Sprintf("erpc_%s_progs", progType)

		if !supportMmapableMaps {
			routes = append(routes, []manager.TailCallRoute{
				{
					ProgArrayName: progArrayName,
					Key:           ERPCResolveParentDentryKey,
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: progType + "_dentry_resolver_parent_erpc_write_user",
					},
				},
				{
					ProgArrayName: progArrayName,
					Key:           ERPCResolvePathWatermarkReaderKey,
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: progType + "_erpc_resolve_path_watermark_reader",
					},
				},
				{
					ProgArrayName: progArrayName,
					Key:           ERPCResolvePathSegmentkReaderKey,
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: progType + "_erpc_resolve_path_segment_reader",
					},
				},
			}...)
		} else {
			routes = append(routes, []manager.TailCallRoute{
				{
					ProgArrayName: progArrayName,
					Key:           ERPCResolveParentDentryKey,
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: progType + "_dentry_resolver_parent_erpc_mmap",
					},
				},
			}...)
		}
	}

	return routes
}
