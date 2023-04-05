#ifndef _HELPERS_SECURITY_PROFILE_SECURITY_PROFILE_H_
#define _HELPERS_SECURITY_PROFILE_SECURITY_PROFILE_H_

#include "constants/custom.h"
#include "helpers/cgroup.h"
#include "helpers/process.h"
#include "maps.h"

__attribute__((always_inline)) int fill_container_id_from_task(struct task_struct *tsk, struct container_context_t *container) {
    u32 tgid = core_get_root_nr_from_task_struct(tsk);
    struct proc_cache_t *pc = get_proc_cache(tgid);
    if (pc) {
        copy_container_id(pc->container.container_id, container->container_id);
        return 1;
    }
    // try to get the container ID directly from the task_struct
    return get_cgroup_name(tsk, container->container_id, sizeof(container->container_id))
}

__attribute__((always_inline)) struct security_profile_process_cookie_t *fetch_and_check_process_cookie(struct task_struct *tsk, struct security_profile_t *profile) {
    u32 tgid = BPF_CORE_READ(tsk, pid);
    struct security_profile_process_cookie_t *process_cookie = bpf_map_lookup_elem(&security_profile_process_cookies, &tgid);
    if (process_cookie) {
        // check the profile cookies match
        if (profile->cookie != process_cookie->profile_cookie) {
            // the profile was updated and the process cookie is no longer reliable, delete the entry and continue to the
            // next section
            bpf_map_delete_elem(&security_profile_process_cookies, &tgid);
        } else {
            return process_cookie;
        }
    }
    return NULL;
}

__attribute__((always_inline)) void fetch_process_profile_cookie(void *ctx, u32 callback) {
    // fetch the current task struct
    struct task_struct *current_task = get_current_task_struct();
    if (current_task == NULL) {
        // we can't do much without the current task, ignore
        goto done;
    }
    current_inode = BPF_CORE_READ(current_task, mm, exe_file, f_inode, i_ino);

    // save callback
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        // shouldn't happen, this helper needs to be called from a syscall event context
        goto abort;
    }
    syscall->security_profile.callback = callback;

    // lookup container ID
    struct container_context_t container = {};
    if (!fill_container_id_from_task(current_task, &container)) {
        // couldn't retrieve the container ID, ignore
        goto done;
    }

    // lookup security profile
    struct security_profile_t *profile = bpf_map_lookup_elem(&security_profiles, &container);
    if (profile == NULL) {
        // this workload doesn't have a profile, ignore
        goto abort;
    }
    syscall->security_profile.profile = *profile;

    // check if the current process has a profile cookie
    struct security_profile_process_cookie_t *process_cookie = fetch_and_check_process_cookie(current_task, profile);
    if (process_cookie) {
        // the process cookie has been found
        syscall->security_profile.process_cookie = process_cookie->process_cookie;
        goto done;
    }

    struct task_struct *last_child = current_task;
    u64 last_inode = current_ino;
    __builtin_memset(syscall->security_profile.process_tree, 0, sizeof(syscall->security_profile.process_tree));
    process_tree[0] = current_task;
    u8 index = 1;

    // go up the process tree to look for the current process in the security profile
    #pragma unroll
    for (int i = 1; i < SECURITY_PROFILE_PROCESS_LOOKUP_MAX_DEPTH; i++) {
        BPF_CORE_READ_INTO(&current_task, current_task, real_parent);
        if (current_task == NULL) {
            // should never happen in a container context, abort
            goto abort;
        }
        current_inode = BPF_CORE_READ(current_task, mm, exe_file, f_inode, i_ino);

        // iterate only on different processes
        if (current_task == current_ino) {
            continue;
        }
        process_tree[index & (SECURITY_PROFILE_PROCESS_LOOKUP_MAX_DEPTH - 1)] = current_task;

        // does this process have a cookie ?
        process_cookie = fetch_and_check_process_cookie(current_task, profile);
        if (process_cookie) {
            // TODO: look process_tree[0:index-1] in the children of process_tree[index]
            goto next;
        }

        // does this process still have a container ID ?
        fill_container_id_from_task(current_task, &container);
        if (container.container_id[0] == 0) {
            // TODO: look process_tree[0:index-1] in the profile, starting with process_tree[index-1] in the root nodes
            goto next;
        }

        last_child = current_task;
        last_inode = current_inode;
        index++;
    }

next:
    // handle the RunC edge case now: are we executing a root process from the runc shim ?
    u32 tgid = core_get_root_nr_from_task_struct(process_tree[index]);
    u32 *cgroup_changed_recently = bpf_map_lookup_elem(&cgroup_write_pids, &tgid);
    if (syscall->type == EVENT_EXEC && index == 1 && cgroup_changed_recently) {
        // TODO: the starting point of the lookup is the process context in the syscall cache, in the root nodes of the profile
    }

    // if process_tree[index] == NULL, we're looking for a root node, else we're looking for the children of process_tree[index]

done:
    bpf_tail_call_compat(ctx, &security_profile_evaluation_progs, callback);
    // jump to callback failed, ignore
    return;

abort:
    return;
}

#endif
