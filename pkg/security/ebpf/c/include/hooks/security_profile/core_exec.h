#ifndef _HOOKS_SECURITY_PROFILE_CORE_EXEC_H_
#define _HOOKS_SECURITY_PROFILE_CORE_EXEC_H_

#include "helpers/security_profile/security_profiles.h"

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(kprobe_security_bprm_check, struct linux_binprm *bprm) {
    fetch_process_profile_cookie(SECURITY_PROFILE_EXEC_KEY);

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&cgroup_write_pids, &tgid);
    return 0;
}

SEC("kprobe/security_profile_exec_callback")
int kprobe_security_profile_exec_callback(struct pt_regs *ctx) {
    return 0;
}

#endif
