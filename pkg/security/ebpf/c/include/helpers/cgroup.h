#ifndef _HELPERS_CGROUP_H_
#define _HELPERS_CGROUP_H_

static __always_inline int get_cgroup_name(struct task_struct *tsk, char *buf, size_t sz) {
    __builtin_memset(buf, 0, sz);

#ifdef COMPILE_CORE
    enum cgroup_subsys_id___local {
        memory_cgrp_id___local = 123, /* value doesn't matter */
    };
    int cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id___local, memory_cgrp_id___local);
#else
    int cgrp_id = memory_cgrp_id;
#endif
    const char *name = BPF_CORE_READ(tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    if (bpf_probe_read_kernel(buf, sz, name) < 0) {
        return 0;
    }

    return 1;
}

#endif
