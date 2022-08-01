#ifndef _EVENTS_H_
#define _EVENTS_H_

#include "bpf_helpers.h"

struct perf_map_stats_t {
    __u64 bytes;
    __u64 count;
    __u64 lost;
};

#define send_event_with_size_ptr_perf(ctx, perf_buffer, stats_map, kernel_event, kernel_event_size)                    \
    perf_ret = bpf_perf_event_output(ctx, &perf_buffer, BPF_F_CURRENT_CPU, kernel_event, kernel_event_size);           \
    u32 cpu = bpf_get_smp_processor_id();                                                                                      \
    struct perf_map_stats_t *stats = bpf_map_lookup_elem(&stats_map, &cpu);                                            \
    if (stats != NULL) {                                                                                               \
        if (!perf_ret) {                                                                                               \
            __sync_fetch_and_add(&stats->bytes, kernel_event_size + 4);                                                \
            __sync_fetch_and_add(&stats->count, 1);                                                                    \
        } else {                                                                                                       \
            __sync_fetch_and_add(&stats->lost, 1);                                                                     \
        }                                                                                                              \
    }

#define send_event_ptr(ctx, perf_buffer, stats_map, kernel_event)                                                      \
    u64 size = sizeof(*kernel_event);                                                                                  \
    int perf_ret;                                                                                                      \
    send_event_with_size_ptr_perf(ctx, perf_buffer, stats_map, kernel_event, size)

#define PERF_BUFFER(name, event_type)                                                                                  \
    struct bpf_map_def SEC("maps/"#name) name = {                                                                      \
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,                                                                         \
        .max_entries = 0,                                                                                              \
        .pinning = 0,                                                                                                  \
        .namespace = "",                                                                                               \
    };                                                                                                                 \
    struct bpf_map_def SEC("maps/"#name"_stats") name##_stats = {                                                      \
        .type = BPF_MAP_TYPE_ARRAY,                                                                                   \
        .key_size = sizeof(u32),                                                                                       \
        .value_size = sizeof(struct perf_map_stats_t),                                                                 \
        .max_entries = 1,                                                                                              \
        .pinning = 0,                                                                                                  \
        .namespace = "",                                                                                               \
    };                                                                                                                 \
    static __always_inline void send_##name(void *ctx, event_type *kernel_event) {                                     \
        send_event_ptr(ctx, name, name##_stats, kernel_event);                                                         \
    }

#endif
