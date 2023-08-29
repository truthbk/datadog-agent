#ifndef _HOOKS_MOUNT_H_
#define _HOOKS_MOUNT_H_

#include "constants/syscall_macro.h"
#include "helpers/events_predicates.h"
#include "helpers/filesystem.h"
#include "helpers/syscalls.h"

HOOK_ENTRY("mnt_want_write")
int hook_mnt_want_write(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mnt_want_write_predicate);
    if (!syscall) {
        return 0;
    }

    struct vfsmount *mnt = (struct vfsmount *)CTX_PARM1(ctx);

    switch (syscall->type) {
    case EVENT_UTIME:
        if (syscall->setattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_CHMOD:
        if (syscall->setattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_CHOWN:
        if (syscall->setattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_RENAME:
        if (syscall->rename.src_file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->rename.src_file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        syscall->rename.target_file.dentry_key.mount_id = syscall->rename.src_file.dentry_key.mount_id;
        break;
    case EVENT_RMDIR:
        if (syscall->rmdir.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->rmdir.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_UNLINK:
        if (syscall->unlink.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->unlink.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_SETXATTR:
        if (syscall->xattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_REMOVEXATTR:
        if (syscall->xattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    }
    return 0;
}

int __attribute__((always_inline)) trace__mnt_want_write_file(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mnt_want_write_file_predicate);
    if (!syscall) {
        return 0;
    }

    struct file *file = (struct file *)CTX_PARM1(ctx);
    struct vfsmount *mnt;
    bpf_probe_read(&mnt, sizeof(mnt), &file->f_path.mnt);

    switch (syscall->type) {
    case EVENT_CHOWN:
        if (syscall->setattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->setattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_SETXATTR:
        if (syscall->xattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_REMOVEXATTR:
        if (syscall->xattr.file.dentry_key.mount_id > 0) {
            return 0;
        }
        syscall->xattr.file.dentry_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    }
    return 0;
}

HOOK_ENTRY("mnt_want_write_file")
int hook_mnt_want_write_file(ctx_t *ctx) {
    return trace__mnt_want_write_file(ctx);
}

// mnt_want_write_file_path was used on old kernels (RHEL 7)
HOOK_ENTRY("mnt_want_write_file_path")
int hook_mnt_want_write_file_path(ctx_t *ctx) {
    return trace__mnt_want_write_file(ctx);
}

HOOK_SYSCALL_COMPAT_ENTRY3(mount, const char*, source, const char*, target, const char*, fstype) {
    struct syscall_cache_t syscall = {
        .type = EVENT_MOUNT,
    };

    cache_syscall(&syscall);

    return 0;
}

HOOK_SYSCALL_ENTRY1(unshare, unsigned long, flags) {
    struct syscall_cache_t syscall = {
        .type = EVENT_UNSHARE_MNTNS,
        .unshare_mntns = {
            .flags = flags,
        },
    };

    // unshare is only used to propagate mounts created when a mount namespace is copied
    if (!(syscall.unshare_mntns.flags & CLONE_NEWNS)) {
        return 0;
    }

    cache_syscall(&syscall);

    return 0;
}

HOOK_SYSCALL_EXIT(unshare) {
    pop_syscall(EVENT_UNSHARE_MNTNS);
    return 0;
}

HOOK_ENTRY("attach_mnt")
int hook_attach_mnt(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_UNSHARE_MNTNS);
    if (!syscall) {
        return 0;
    }

    syscall->unshare_mntns.newmnt = (struct mount *)CTX_PARM1(ctx);
    syscall->unshare_mntns.parent = (struct mount *)CTX_PARM2(ctx);
    struct mountpoint *mp = (struct mountpoint *)CTX_PARM3(ctx);
    syscall->unshare_mntns.mp_dentry = get_mountpoint_dentry(mp);

    resolve_unshared_mnt(ctx, syscall, DR_KPROBE_OR_FENTRY);

    return 0;
}

HOOK_ENTRY("__attach_mnt")
int hook___attach_mnt(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_UNSHARE_MNTNS);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM1(ctx);

    // check if mnt has already been processed in case both attach_mnt and __attach_mnt are loaded
    if (syscall->unshare_mntns.newmnt == newmnt) {
        return 0;
    }

    syscall->unshare_mntns.newmnt = newmnt;
    syscall->unshare_mntns.parent = (struct mount *)CTX_PARM2(ctx);
    syscall->unshare_mntns.mp_dentry = get_mount_mountpoint_dentry(syscall->unshare_mntns.newmnt);

    resolve_unshared_mnt(ctx, syscall, DR_KPROBE_OR_FENTRY);

    return 0;
}

HOOK_ENTRY("mnt_set_mountpoint")
int hook_mnt_set_mountpoint(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_UNSHARE_MNTNS);
    if (!syscall) {
        return 0;
    }

    struct mount *newmnt = (struct mount *)CTX_PARM3(ctx);

    // check if mnt has already been processed in case both attach_mnt and __attach_mnt are loaded
    if (syscall->unshare_mntns.newmnt == newmnt) {
        return 0;
    }

    syscall->unshare_mntns.newmnt = newmnt;
    syscall->unshare_mntns.parent = (struct mount *)CTX_PARM1(ctx);
    struct mountpoint *mp = (struct mountpoint *)CTX_PARM2(ctx);
    syscall->unshare_mntns.mp_dentry = get_mountpoint_dentry(mp);

    resolve_unshared_mnt(ctx, syscall, DR_KPROBE_OR_FENTRY);
    return 0;
}

int __attribute__((always_inline)) dr_unshare_mntns_callback(void *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_UNSHARE_MNTNS);
    if (!syscall) {
        return 0;
    }

    struct unshare_mntns_event_t event = {
        .mountfields.mount_id = get_mount_mount_id(syscall->unshare_mntns.newmnt),
        .mountfields.device = get_mount_dev(syscall->unshare_mntns.newmnt),
        .mountfields.mp_key = syscall->unshare_mntns.mp_dentry_key,
        .mountfields.bind_src_mount_id = 0, // do not consider mnt ns copies as bind mounts
    };

    if (event.mountfields.mount_id == 0 && event.mountfields.device == 0) {
        return 0;
    }

    bpf_probe_read_str(&event.mountfields.fstype, FSTYPE_LEN, (void*)syscall->unshare_mntns.fstype);
    fill_dr_ringbuf_ref_from_ctx(&event.mountfields.mp_ref);

    send_event(ctx, EVENT_UNSHARE_MNTNS, event);

    return 0;
}

SEC("kprobe/dr_unshare_mntns_callback")
int kprobe_dr_unshare_mntns_callback(struct pt_regs *ctx) {
    return dr_unshare_mntns_callback(ctx);
}

#ifdef USE_FENTRY

TAIL_CALL_TARGET("dr_unshare_mntns_callback")
int fentry_dr_unshare_mntns_callback(ctx_t *ctx) {
    return dr_unshare_mntns_callback(ctx);
}

#endif // USE_FENTRY

HOOK_ENTRY("clone_mnt")
int hook_clone_mnt(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    if (syscall->mount.bind_src_mnt || syscall->mount.newmnt) {
        return 0;
    }

    syscall->mount.bind_src_mnt = (struct mount *)CTX_PARM1(ctx);

    syscall->mount.bind_src_key.mount_id = get_mount_mount_id(syscall->mount.bind_src_mnt);
    struct dentry *mount_dentry = get_mount_mountpoint_dentry(syscall->mount.bind_src_mnt);
    syscall->mount.bind_src_key.ino = get_dentry_ino(mount_dentry);
    update_path_id(&syscall->mount.bind_src_key, 0);

    syscall->resolver.key = syscall->mount.bind_src_key;
    syscall->resolver.dentry = mount_dentry;
    syscall->resolver.discarder_type = 0;
    syscall->resolver.callback = DR_NO_CALLBACK;
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;

    resolve_dentry(ctx, DR_KPROBE_OR_FENTRY);

    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(EVENT_MOUNT);

    return 0;
}

HOOK_ENTRY("attach_recursive_mnt")
int hook_attach_recursive_mnt(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    if (syscall->mount.newmnt) {
        return 0;
    }

    syscall->mount.newmnt = (struct mount *)CTX_PARM1(ctx);
    syscall->mount.parent = (struct mount *)CTX_PARM2(ctx);
    syscall->mount.mp = (struct mountpoint *)CTX_PARM3(ctx);

    // resolve root dentry
    struct dentry *dentry = get_vfsmount_dentry(get_mount_vfsmount(syscall->mount.newmnt));
    syscall->mount.root_key.mount_id = get_mount_mount_id(syscall->mount.newmnt);
    syscall->mount.root_key.ino = get_dentry_ino(dentry);
    update_path_id(&syscall->mount.root_key, 0);

    struct super_block *sb = get_dentry_sb(dentry);
    struct file_system_type *s_type = get_super_block_fs(sb);
    bpf_probe_read(&syscall->mount.fstype, sizeof(syscall->mount.fstype), &s_type->name);

    syscall->resolver.key = syscall->mount.root_key;
    syscall->resolver.dentry = dentry;
    syscall->resolver.discarder_type = 0;
    syscall->resolver.callback = DR_NO_CALLBACK;
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;

    resolve_dentry(ctx, DR_KPROBE_OR_FENTRY);

    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(EVENT_MOUNT);

    return 0;
}

HOOK_ENTRY("propagate_mnt")
int hook_propagate_mnt(ctx_t *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    if (syscall->mount.newmnt) {
        return 0;
    }

    syscall->mount.parent = (struct mount *)CTX_PARM1(ctx);
    syscall->mount.mp = (struct mountpoint *)CTX_PARM2(ctx);
    syscall->mount.newmnt = (struct mount *)CTX_PARM3(ctx);

    // resolve root dentry
    struct dentry *dentry = get_vfsmount_dentry(get_mount_vfsmount(syscall->mount.newmnt));
    syscall->mount.root_key.mount_id = get_mount_mount_id(syscall->mount.newmnt);
    syscall->mount.root_key.ino = get_dentry_ino(dentry);
    update_path_id(&syscall->mount.root_key, 0);

    struct super_block *sb = get_dentry_sb(dentry);
    struct file_system_type *s_type = get_super_block_fs(sb);
    bpf_probe_read(&syscall->mount.fstype, sizeof(syscall->mount.fstype), &s_type->name);

    syscall->resolver.key = syscall->mount.root_key;
    syscall->resolver.dentry = dentry;
    syscall->resolver.discarder_type = 0;
    syscall->resolver.callback = DR_NO_CALLBACK;
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;

    resolve_dentry(ctx, DR_KPROBE_OR_FENTRY);

    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(EVENT_MOUNT);

    return 0;
}

// regular mount stuff

int __attribute__((always_inline)) sys_mount_ret(void *ctx, int retval, int dr_type) {
    if (retval) {
        pop_syscall(EVENT_MOUNT);
        return 0;
    }

    struct syscall_cache_t *syscall = peek_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    if (syscall->mount.newmnt) {
        fill_dr_ringbuf_ref_from_ctx(&syscall->mount.root_ref);
    }

    u32 mount_id = get_mount_mount_id(syscall->mount.parent);

    struct dentry *dentry = get_mountpoint_dentry(syscall->mount.mp);
    struct dentry_key_t mp_key = {
        .mount_id = mount_id,
        .ino = get_dentry_ino(dentry),
        .path_id = get_path_id(mount_id, 0),
    };
    syscall->mount.mp_key = mp_key;

    syscall->resolver.key = mp_key;
    syscall->resolver.dentry = dentry;
    syscall->resolver.discarder_type = 0;
    syscall->resolver.callback = DR_CALLBACK_MOUNT;
    syscall->resolver.iteration = 0;
    syscall->resolver.ret = 0;
    syscall->resolver.sysretval = retval;

    resolve_dentry(ctx, dr_type);

    // if the tail call fails, we need to pop the syscall cache entry
    pop_syscall(EVENT_MOUNT);
    return 0;
}

HOOK_SYSCALL_COMPAT_EXIT(mount) {
    int retval = SYSCALL_PARMRET(ctx);
    return sys_mount_ret(ctx, retval, DR_KPROBE_OR_FENTRY);
}

SEC("tracepoint/handle_sys_mount_exit")
int tracepoint_handle_sys_mount_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    return sys_mount_ret(args, args->ret, DR_TRACEPOINT);
}

int __attribute__((always_inline)) dr_mount_callback(void *ctx) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_MOUNT);
    if (!syscall) {
        return 0;
    }

    s64 retval = syscall->resolver.sysretval;

    struct mount_event_t event = {
        .syscall.retval = retval,
        .mountfields.mount_id = get_mount_mount_id(syscall->mount.newmnt),
        .mountfields.device = get_mount_dev(syscall->mount.newmnt),
        .mountfields.mp_key = syscall->mount.mp_key,
        .mountfields.root_key = syscall->mount.root_key,
        .mountfields.bind_src_mount_id = syscall->mount.bind_src_key.mount_id,
    };

    if (event.mountfields.mount_id == 0 && event.mountfields.device == 0) {
        return 0;
    }

    bpf_probe_read_str(&event.mountfields.fstype, FSTYPE_LEN, (void*)syscall->mount.fstype);

    fill_dr_ringbuf_ref_from_ctx(&event.mountfields.mp_ref);
    event.mountfields.root_ref = syscall->mount.root_ref;

    struct proc_cache_t *entry = fill_process_context(&event.process);
    fill_container_context(entry, &event.container);
    fill_span_context(&event.span);

    send_event(ctx, EVENT_MOUNT, event);

    return 0;
}

SEC("kprobe/dr_mount_callback")
int kprobe_dr_mount_callback(struct pt_regs *ctx) {
    return dr_mount_callback(ctx);
}

#ifdef USE_FENTRY

TAIL_CALL_TARGET("dr_mount_callback")
int fentry_dr_mount_callback(ctx_t *ctx) {
    return dr_mount_callback(ctx);
}

#endif // USE_FENTRY

SEC("tracepoint/dr_mount_callback")
int tracepoint_dr_mount_callback(struct tracepoint_syscalls_sys_exit_t *args) {
    return dr_mount_callback(args);
}

#endif
