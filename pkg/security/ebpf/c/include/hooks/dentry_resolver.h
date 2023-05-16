#ifndef _HOOKS_DENTRY_RESOLVER_H_
#define _HOOKS_DENTRY_RESOLVER_H_

#include "constants/offsets/filesystem.h"
#include "helpers/dentry_resolver.h"
#include "helpers/discarders.h"
#include "helpers/syscalls.h"

int __attribute__((always_inline)) dentry_resolver_parent_erpc_write_user(void *ctx) {
    u32 key = 0;
    u32 resolution_err = 0;

    struct dr_erpc_state_t *state = bpf_map_lookup_elem(&dr_erpc_state, &key);
    if (state == NULL) {
        return 0;
    }

    // resolve segment and write in buffer
    struct dentry_key_t dentry_key = state->key;
    struct dentry_leaf_t *map_value = bpf_map_lookup_elem(&dentries, &dentry_key);
    if (map_value == NULL) {
        resolution_err = DR_ERPC_CACHE_MISS;
        goto exit;
    }

    if (sizeof(map_value->parent) > state->buffer_size) {
        // make sure we do not write outside of the provided buffer
        resolution_err = DR_ERPC_BUFFER_SIZE;
        goto exit;
    }

    int ret = bpf_probe_write_user((void *) state->userspace_buffer, &map_value->parent, sizeof(map_value->parent));
    if (ret < 0) {
        resolution_err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
        goto exit;
    }
    ret = bpf_probe_write_user((void *) state->userspace_buffer + offsetof(struct dentry_key_t, path_id), &state->challenge, sizeof(state->challenge));
    if (ret < 0) {
        resolution_err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
        goto exit;
    }

exit:
    monitor_resolution_err(resolution_err);
    return 0;
}

SEC("kprobe/dentry_resolver_parent_erpc_write_user")
int kprobe_dentry_resolver_parent_erpc_write_user(struct pt_regs *ctx) {
    return dentry_resolver_parent_erpc_write_user(ctx);
}

#ifdef USE_FENTRY

TAIL_CALL_TARGET("dentry_resolver_parent_erpc_write_user")
int fentry_dentry_resolver_parent_erpc_write_user(ctx_t *ctx) {
    return dentry_resolver_parent_erpc_write_user(ctx);
}

#endif // USE_FENTRY

int __attribute__((always_inline)) dentry_resolver_parent_erpc_mmap(void *ctx) {
    u32 key = 0;
    u32 resolution_err = 0;
    char *mmapped_userspace_buffer = NULL;

    struct dr_erpc_state_t *state = bpf_map_lookup_elem(&dr_erpc_state, &key);
    if (state == NULL) {
        return 0;
    }

    mmapped_userspace_buffer = bpf_map_lookup_elem(&dr_erpc_buffer, &key);
    if (mmapped_userspace_buffer == NULL) {
        resolution_err = DR_ERPC_UNKNOWN_ERROR;
        goto exit;
    }

    // resolve segment and write in buffer
    struct dentry_key_t dentry_key = state->key;
    struct dentry_leaf_t *map_value = bpf_map_lookup_elem(&dentries, &dentry_key);
    if (map_value == NULL) {
        resolution_err = DR_ERPC_CACHE_MISS;
        goto exit;
    }

    if (sizeof(map_value->parent) > state->buffer_size) {
        // make sure we do not write outside of the provided buffer
        resolution_err = DR_ERPC_BUFFER_SIZE;
        goto exit;
    }

    int ret = bpf_probe_read((void *) mmapped_userspace_buffer, sizeof(map_value->parent), &map_value->parent);
    if (ret < 0) {
        resolution_err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
        goto exit;
    }
    ret = bpf_probe_read((void *) mmapped_userspace_buffer + (offsetof(struct dentry_key_t, path_id) & 0x7FFF), sizeof(state->challenge), &state->challenge);
    if (ret < 0) {
        resolution_err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
        goto exit;
    }

exit:
    monitor_resolution_err(resolution_err);
    return 0;
}

SEC("kprobe/dentry_resolver_parent_erpc_mmap")
int kprobe_dentry_resolver_parent_erpc_mmap(struct pt_regs *ctx) {
    return dentry_resolver_parent_erpc_mmap(ctx);
}

#ifdef USE_FENTRY

TAIL_CALL_TARGET("dentry_resolver_parent_erpc_mmap")
int fentry_dentry_resolver_parent_erpc_mmap(ctx_t *ctx) {
    return dentry_resolver_parent_erpc_mmap(ctx);
}

#endif // USE_FENTRY

#endif
