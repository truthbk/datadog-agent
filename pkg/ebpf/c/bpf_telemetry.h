#ifndef BPF_TELEMETRY_H
#define BPF_TELEMETRY_H

#include "bpf_helpers.h"
#include "telemetry_types.h"
#include "map-defs.h"

#define MAP_ID(map) map##_##telemetry_id

BPF_ARRAY_MAP(map_err_telemetry_map,errors_telemetry_t,MAPS_MAX_ELEMENT)
BPF_ARRAY_MAP(helper_err_telemetry_map,errors_telemetry_t,PROBES_MAX_ELEMENT * MAX_TELEMETRY_INDEX)

#define PATCH_TARGET_TELEMETRY -1
static void *(*bpf_telemetry_update_patch)(unsigned long, ...) = (void *)PATCH_TARGET_TELEMETRY;

#define map_update_with_telemetry(fn, map, args...)                                \
    ({                                                                             \
        long errno_ret, errno_slot;                                                \
        errno_ret = fn(&map, args);                                                \
        if (errno_ret < 0) {                                                       \
            /* the array_id will be valid, otherwise the macro won't compile */     \
            u32 array_id = (u32)MAP_ID(map);                                       \
            errors_telemetry_t *entry =                                            \
                bpf_map_lookup_elem(&map_err_telemetry_map, &array_id);            \
            if (entry) {                                                           \
                errno_slot = errno_ret * -1;                                       \
                if (errno_slot >= T_MAX_ERRNO) {                                   \
                    errno_slot = T_MAX_ERRNO - 1;                                  \
                    errno_slot &= (T_MAX_ERRNO - 1);                               \
                }                                                                  \
                errno_slot &= (T_MAX_ERRNO - 1);                                   \
                long *target = &entry->err_count[errno_slot];                      \
                unsigned long add = 1;                                             \
                /* Patched instruction for 4.14+: __sync_fetch_and_add(target, 1);
                 * This patch point is placed here because the above instruction
                 * fails on the 4.4 verifier. On 4.4 this instruction is replaced
                 * with a nop: r1 = r1 */                                          \
                bpf_telemetry_update_patch((unsigned long)target, add);            \
            }                                                                      \
        }                                                                          \
        errno_ret;                                                                 \
    })

#define bpf_map_update_with_telemetry(map, key, val, flags) \
    map_update_with_telemetry(bpf_map_update_elem, map, key, val, flags)





#define MK_FN_INDX(fn) FN_INDX_##fn

#define FN_INDX_bpf_probe_read read_indx

#define FN_INDX_bpf_probe_read_kernel read_kernel_indx
#define FN_INDX_bpf_probe_read_kernel_str read_kernel_indx

#define FN_INDX_bpf_probe_read_user read_user_indx
#define FN_INDX_bpf_probe_read_user_str read_user_indx

#define FN_INDX_bpf_skb_load_bytes skb_load_bytes
#define FN_INDX_bpf_perf_event_output perf_event_output

#define helper_with_telemetry(fn, ...)                                                          \
    ({                                                                                          \
        long errno_ret = fn(__VA_ARGS__);                                                       \
        errno_ret;                                                                              \
    })                                                                                     \

#define bpf_probe_read_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read, __VA_ARGS__)

#define bpf_probe_read_str_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read_str, __VA_ARGS__)

#define bpf_probe_read_user_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read_user, __VA_ARGS__)

#define bpf_probe_read_user_str_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read_user_str, __VA_ARGS__)

#define bpf_probe_read_kernel_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read_kernel, __VA_ARGS__)

#define bpf_probe_read_kernel_str_with_telemetry(...) \
    helper_with_telemetry(bpf_probe_read_kernel_str, __VA_ARGS__)

#define bpf_skb_load_bytes_with_telemetry(...) \
    helper_with_telemetry(bpf_skb_load_bytes, __VA_ARGS__)

#define bpf_perf_event_output_with_telemetry(...) \
    helper_with_telemetry(bpf_perf_event_output, __VA_ARGS__)


//#define bpf_probe_read_with_telemetry(probe, ...) \
//    helper_with_telemetry(probe, bpf_probe_read, __VA_ARGS__)
//
//#define bpf_probe_read_str_with_telemetry(probe, ...) \
//    helper_with_telemetry(probe, bpf_probe_read_str, __VA_ARGS__)
//
//#define bpf_probe_read_user_with_telemetry(probe,...) \
//    helper_with_telemetry(probe, bpf_probe_read_user, __VA_ARGS__)
//
//#define bpf_probe_read_user_str_with_telemetry(probe,...) \
//    helper_with_telemetry(probe, bpf_probe_read_user_str, __VA_ARGS__)
//
//#define bpf_probe_read_kernel_with_telemetry(probe,...) \
//    helper_with_telemetry(probe, bpf_probe_read_kernel, __VA_ARGS__)
//
//#define bpf_probe_read_kernel_str_with_telemetry(probe, ...) \
//    helper_with_telemetry(probe, bpf_probe_read_kernel_str, __VA_ARGS__)
//
//#define bpf_skb_load_bytes_with_telemetry(probe, ...) \
//    helper_with_telemetry(probe, bpf_skb_load_bytes, __VA_ARGS__)
//
//#define bpf_perf_event_output_with_telemetry(probe, ...) \
//    helper_with_telemetry(probe, bpf_perf_event_output, __VA_ARGS__)

#endif // BPF_TELEMETRY_H
