#ifndef _HELPERS_PATH_RESOLVER_H_
#define _HELPERS_PATH_RESOLVER_H_

#include "maps.h"
#include "constants/custom.h"

int __attribute__((always_inline)) tail_call_dr_progs(void *ctx, int dr_type, int key) {
    switch (dr_type) {
    case DR_KPROBE:
        bpf_tail_call_compat(ctx, &path_resolver_kprobe_progs, key);
        break;
    case DR_FENTRY:
        bpf_tail_call_compat(ctx, &path_resolver_fentry_progs, key);
        break;
    case DR_TRACEPOINT:
        bpf_tail_call_compat(ctx, &path_resolver_tracepoint_progs, key);
        break;
    }
    return 0;
}

int __attribute__((always_inline)) resolve_path(void *ctx, int dr_type) {
    return tail_call_dr_progs(ctx, dr_type, PR_PROGKEY_ENTRYPOINT);
}

void __attribute__((always_inline)) fill_path_ring_buffer_ref(struct pr_ring_buffer_ref_t *path_ref) {
    u32 zero = 0;
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return;
    }
    path_ref->read_cursor = ringbuf_ctx->read_cursor;
    path_ref->watermark = ringbuf_ctx->watermark;
    path_ref->len = ringbuf_ctx->len;
    path_ref->cpu = ringbuf_ctx->cpu;
}

u32 __attribute__((always_inline)) rb_get_tail_length(struct pr_ring_buffer_ctx *ringbuf_ctx) {
    ringbuf_ctx->write_cursor %= PR_RING_BUFFER_SIZE;
    return PR_RING_BUFFER_SIZE - ringbuf_ctx->write_cursor;
}

void __attribute__((always_inline)) rb_push_str(struct pr_ring_buffer *rb, struct pr_ring_buffer_ctx *ringbuf_ctx, char *str, u32 const_len) {
    ringbuf_ctx->write_cursor %= PR_RING_BUFFER_SIZE;
    if (ringbuf_ctx->write_cursor + const_len <= PR_RING_BUFFER_SIZE) {
        long len = bpf_probe_read_str(&rb->buffer[ringbuf_ctx->write_cursor], const_len, str);
        if (len > 0) {
            // bpf_probe_read_str will set the last byte to NULL, so remove 1 from the total len so that it gets overwritten on the next push
            ringbuf_ctx->write_cursor = (ringbuf_ctx->write_cursor + len - 1) % PR_RING_BUFFER_SIZE;
            ringbuf_ctx->len += (len - 1);
        }
    }
}

void __attribute__((always_inline)) rb_push_watermark(struct pr_ring_buffer *rb, struct pr_ring_buffer_ctx *ringbuf_ctx) {
#pragma unroll
    for (unsigned int i = 0; i < sizeof(ringbuf_ctx->watermark); i++) {
        rb->buffer[ringbuf_ctx->write_cursor++ % PR_RING_BUFFER_SIZE] = *(((char *)&ringbuf_ctx->watermark) + i);
    }
    ringbuf_ctx->write_cursor %= PR_RING_BUFFER_SIZE;
    ringbuf_ctx->len += sizeof(ringbuf_ctx->watermark);
}

void __attribute__((always_inline)) rb_push_char(struct pr_ring_buffer *rb, struct pr_ring_buffer_ctx *ringbuf_ctx, char c) {
    rb->buffer[ringbuf_ctx->write_cursor++ % PR_RING_BUFFER_SIZE] = c;
    ringbuf_ctx->write_cursor %= PR_RING_BUFFER_SIZE;
    ringbuf_ctx->len += 1;
}

int __attribute__((always_inline)) rb_prepare_ctx() {
    u32 zero = 0;
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return 1;
    }

    u32 cpu = bpf_get_smp_processor_id();
    struct pr_ring_buffer *rb = bpf_map_lookup_elem(&pr_ringbufs, &cpu);
    if (!rb) {
        return 1;
    }

    ringbuf_ctx->read_cursor = ringbuf_ctx->write_cursor;
    ringbuf_ctx->watermark = bpf_ktime_get_ns();
    ringbuf_ctx->len = 0;
    ringbuf_ctx->cpu = cpu;

    rb_push_watermark(rb, ringbuf_ctx);

    return 0;
}

#endif
