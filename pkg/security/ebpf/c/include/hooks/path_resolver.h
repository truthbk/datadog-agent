#ifndef _HOOKS_PATH_RESOLVER_H_
#define _HOOKS_PATH_RESOLVER_H_

#include "maps.h"
#include "constants/custom.h"

#define PR_MAX_SEGMENT_LENGTH 255
#define PR_MAX_ITERATION_DEPTH 8
#define PR_MAX_TAIL_CALL 28

#define FNV_OFFSET_BASIS    ((__u64)14695981039346656037U)
#define FNV_PRIME           ((__u64)1099511628211U)

void __attribute__((always_inline)) cleanup_ringbuf_ctx(struct pr_ring_buffer_ctx *ringbuf_ctx) {
    ringbuf_ctx->write_cursor = ringbuf_ctx->read_cursor;
    ringbuf_ctx->watermark = 0;
    ringbuf_ctx->len = 0;
}

int __attribute__((always_inline)) resolve_path_tail_call(void *ctx, struct dentry_resolver_input_t *input, struct pr_ring_buffer *rb, struct pr_ring_buffer_ctx *ringbuf_ctx) {
    u32 zero = 0;
    struct dentry_leaf_t map_value = {};
    struct dentry_key_t key = input->key;
    struct dentry_key_t next_key = input->key;
    struct qstr qstr;
    struct dentry *dentry = input->dentry;
    struct dentry *d_parent = NULL;
    char name[PR_MAX_SEGMENT_LENGTH + 1] = {0};

    if (key.ino == 0) {
        cleanup_ringbuf_ctx(ringbuf_ctx);
        return DENTRY_INVALID;
    }

    struct is_discarded_by_inode_t *params = bpf_map_lookup_elem(&is_discarded_by_inode_gen, &zero);
    if (!params) {
        cleanup_ringbuf_ctx(ringbuf_ctx);
        return DENTRY_ERROR;
    }
    *params = (struct is_discarded_by_inode_t){
        .discarder_type = input->discarder_type,
        .now = bpf_ktime_get_ns(),
    };

#pragma unroll
    for (int i = 0; i < PR_MAX_ITERATION_DEPTH; i++) {
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        key = next_key;
        if (dentry != d_parent) {
            next_key.ino = get_dentry_ino(d_parent);
        } else {
            next_key.ino = 0;
            next_key.mount_id = 0;
        }

        if (input->discarder_type && i <= 3) {
            params->discarder.dentry_key.ino = key.ino;
            params->discarder.dentry_key.mount_id = key.mount_id;
            params->discarder.is_leaf = i == 0;

            if (is_discarded_by_inode(params)) {
                if (input->flags & ACTIVITY_DUMP_RUNNING) {
                    input->flags |= SAVED_BY_ACTIVITY_DUMP;
                } else {
                    cleanup_ringbuf_ctx(ringbuf_ctx);
                    return DENTRY_DISCARDED;
                }
            }
        }

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        long len = bpf_probe_read_str(&name, sizeof(name), (void *)qstr.name);
        // len -= 1; // do not count trailing zero
        if (len <= 0 || name[0] == 0) {
            cleanup_ringbuf_ctx(ringbuf_ctx);
            map_value.parent.ino = 0;
            map_value.parent.mount_id = 0;
            bpf_map_update_elem(&dentries, &key, &map_value, BPF_ANY);
            return DENTRY_ERROR;
        }

        if (len == 2 && name[0] == '/') {
            if (ringbuf_ctx->len == 0) { // we want to push '/' only if we are resolving a root path
                rb_push_char(rb, ringbuf_ctx, '/');
            }
            rb_push_char(rb, ringbuf_ctx, '\0');
            // mark the path resolution as complete which will stop the tail calls
            input->key.ino = 0;
            map_value.parent.ino = 0;
            map_value.parent.mount_id = 0;
            bpf_map_update_elem(&dentries, &key, &map_value, BPF_ANY);
            return i + 1;
        }

        u32 rb_tail_len = rb_get_tail_length(ringbuf_ctx);
        if (rb_tail_len < sizeof(name)) {
            rb->buffer[ringbuf_ctx->write_cursor % PR_RING_BUFFER_SIZE] = '\0';
            ringbuf_ctx->len += rb_tail_len;
            ringbuf_ctx->write_cursor = 0;
        }

        rb_push_str(rb, ringbuf_ctx, &name[0], sizeof(name));
        rb_push_char(rb, ringbuf_ctx, '/');

        map_value.parent = next_key;
        bpf_map_update_elem(&dentries, &key, &map_value, BPF_ANY);
        dentry = d_parent;
    }

    if (input->iteration == PR_MAX_TAIL_CALL) {
        cleanup_ringbuf_ctx(ringbuf_ctx);
        ringbuf_ctx->len = ~0;
        map_value.parent.mount_id = 0;
        map_value.parent.ino = 0;
        bpf_map_update_elem(&dentries, &next_key, &map_value, BPF_ANY);
        return DENTRY_ERROR;
    }

    // prepare for the next iteration
    input->dentry = d_parent;
    input->key = next_key;
    return PR_MAX_ITERATION_DEPTH;
}

#define path_resolver_loop(ctx, pr_progs_map)                                                                          \
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);                                                         \
    if (!syscall)                                                                                                      \
        return 0;                                                                                                      \
                                                                                                                       \
    u32 zero = 0;                                                                                                      \
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);                              \
    if (!ringbuf_ctx) {                                                                                                \
        return 0;                                                                                                      \
    }                                                                                                                  \
                                                                                                                       \
    u32 cpu = bpf_get_smp_processor_id();                                                                              \
    struct pr_ring_buffer *rb = bpf_map_lookup_elem(&pr_ringbufs, &cpu);                                               \
    if (!rb) {                                                                                                         \
        return 0;                                                                                                      \
    }                                                                                                                  \
                                                                                                                       \
    syscall->resolver.iteration++;                                                                                     \
    syscall->resolver.ret = resolve_path_tail_call(ctx, &syscall->resolver, rb, ringbuf_ctx);                          \
                                                                                                                       \
    if (syscall->resolver.ret > 0) {                                                                                   \
        if (syscall->resolver.iteration < PR_MAX_TAIL_CALL && syscall->resolver.key.ino != 0) {                        \
            bpf_tail_call_compat(ctx, pr_progs_map, PR_PROGKEY_LOOP);                                                  \
        }                                                                                                              \
                                                                                                                       \
        syscall->resolver.ret += PR_MAX_ITERATION_DEPTH * (syscall->resolver.iteration - 1);                           \
    }                                                                                                                  \
                                                                                                                       \
    rb_push_watermark(rb, ringbuf_ctx);                                                                                \
                                                                                                                       \
    if (syscall->resolver.callback >= 0) {                                                                             \
        bpf_tail_call_compat(ctx, pr_progs_map, syscall->resolver.callback);                                           \
    }                                                                                                                  \

SEC("kprobe/path_resolver_entrypoint")
int kprobe_path_resolver_entrypoint(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        return 0;
    }

    if (is_activity_dump_running(ctx, bpf_get_current_pid_tgid() >> 32, bpf_ktime_get_ns(), syscall->type)) {
        syscall->resolver.flags |= ACTIVITY_DUMP_RUNNING;
    }

    if (rb_prepare_ctx()) {
        return 0;
    }

    syscall->resolver.iteration = 0;
    bpf_tail_call_compat(ctx, &path_resolver_kprobe_progs, PR_PROGKEY_LOOP);
    return 0;
}

SEC("tracepoint/path_resolver_entrypoint")
int tracepoint_path_resolver_entrypoint(void *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        return 0;
    }

    if (is_activity_dump_running(ctx, bpf_get_current_pid_tgid() >> 32, bpf_ktime_get_ns(), syscall->type)) {
        syscall->resolver.flags |= ACTIVITY_DUMP_RUNNING;
    }

    if (rb_prepare_ctx()) {
        return 0;
    }

    syscall->resolver.iteration = 0;
    bpf_tail_call_compat(ctx, &path_resolver_tracepoint_progs, PR_PROGKEY_LOOP);
    return 0;
}

SEC("kprobe/path_resolver_loop")
int kprobe_path_resolver_loop(struct pt_regs *ctx) {
    path_resolver_loop(ctx, &path_resolver_kprobe_progs);
    return 0;
}

SEC("tracepoint/path_resolver_loop")
int tracepoint_path_resolver_loop(void *ctx) {
    path_resolver_loop(ctx, &path_resolver_tracepoint_progs);
    return 0;
}

SEC("kprobe/erpc_resolve_path_watermark_reader")
int kprobe_erpc_resolve_path_watermark_reader(void *ctx) {
    u32 zero = 0, err = 0;
    struct dr_erpc_state_t *state = bpf_map_lookup_elem(&dr_erpc_state, &zero);
    if (!state) {
        return 0;
    }

    struct pr_ring_buffer *rb = bpf_map_lookup_elem(&pr_ringbufs, &state->path_ref.cpu);
    if (!rb) {
        err = DR_ERPC_CACHE_MISS; // TODO: use a specific error type for malformed request
        goto exit;
    }

    if (state->path_reader_state == READ_FRONTWATERMARK) {
        int ret = bpf_probe_write_user((void *)state->userspace_buffer, &state->challenge, sizeof(state->challenge));
        if (ret < 0) {
            err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
            goto exit;
        }
        state->cursor += sizeof(state->challenge);
    }

    if (state->path_ref.read_cursor + sizeof(state->path_ref.watermark) <= PR_RING_BUFFER_SIZE) {
        int ret = bpf_probe_write_user((void *)state->userspace_buffer + state->cursor, &rb->buffer[state->path_ref.read_cursor], sizeof(state->path_ref.watermark));
        if (ret < 0) {
            err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
            goto exit;
        }
        state->path_ref.read_cursor += sizeof(state->path_ref.watermark);
        state->cursor += sizeof(state->path_ref.watermark);
    } else {
#pragma unroll
        for (int i = 0; i < sizeof(state->path_ref.watermark); i++) {
            int ret = bpf_probe_write_user((void *)state->userspace_buffer + state->cursor, &rb->buffer[state->path_ref.read_cursor % PR_RING_BUFFER_SIZE], 1);
            if (ret < 0) {
                err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
                goto exit;
            }
            state->path_ref.read_cursor++;
            state->cursor++;
        }
    }

    if (state->path_reader_state == READ_FRONTWATERMARK) {
        state->path_reader_state = READ_PATHSEGMENT;
        tail_call_erpc_progs(ctx, DR_KPROBE_OR_FENTRY, ERPC_RESOLVE_PATH_SEGMENT_READER_KEY);
        err = DR_ERPC_TAIL_CALL_ERROR;
    }

exit:
    monitor_resolution_err(err);
    return 0;
}


SEC("kprobe/erpc_resolve_path_segment_reader")
int kprobe_erpc_resolve_path_segment_reader(void *ctx) {
    u32 zero = 0, err = 0;
    char path_chunk[32] = {0};
    struct dr_erpc_state_t *state = bpf_map_lookup_elem(&dr_erpc_state, &zero);
    if (!state) {
        return 0;
    }

    struct pr_ring_buffer *rb = bpf_map_lookup_elem(&pr_ringbufs, &state->path_ref.cpu);
    if (!rb) {
        err = DR_ERPC_CACHE_MISS; // TODO: use a specific error type for malformed request
        goto exit;
    }

#pragma unroll
    for (int i = 0; i < 32; i++) {
        if (state->path_ref.read_cursor == state->path_end_cursor) {
            state->path_reader_state = READ_BACKWATERMARK;
            tail_call_erpc_progs(ctx, DR_KPROBE_OR_FENTRY, ERPC_RESOLVE_PATH_WATERMARK_READER_KEY);
            err = DR_ERPC_TAIL_CALL_ERROR;
            goto exit;
        }
        long len = bpf_probe_read_str(path_chunk, sizeof(path_chunk), &rb->buffer[state->path_ref.read_cursor % PR_RING_BUFFER_SIZE]);
        if (len <= 0) {
            err = DR_ERPC_CACHE_MISS; // TODO: use a specific error type for this
            goto exit;
        }
        int ret = bpf_probe_write_user((void *)state->userspace_buffer + state->cursor, path_chunk, sizeof(path_chunk));
        if (ret < 0) {
            err = ret == -14 ? DR_ERPC_WRITE_PAGE_FAULT : DR_ERPC_UNKNOWN_ERROR;
            goto exit;
        }
        if (len == sizeof(path_chunk) && rb->buffer[(state->path_ref.read_cursor + sizeof(path_chunk) - 1) % PR_RING_BUFFER_SIZE] != '\0') {
            state->path_ref.read_cursor -= 1;
            state->cursor -= 1;
        }
        state->path_ref.read_cursor += len;
        state->cursor += len;
    }

    tail_call_erpc_progs(ctx, DR_KPROBE_OR_FENTRY, ERPC_RESOLVE_PATH_SEGMENT_READER_KEY);
    err = DR_ERPC_TAIL_CALL_ERROR;

exit:
    monitor_resolution_err(err);
    return 0;
}

#endif
