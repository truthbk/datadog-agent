#ifndef __IPV6_H
#define __IPV6_H

#include "ktypes.h"
#include "bpf_core_read.h"
#include "bpf_telemetry.h"

#include "defs.h"

#ifdef COMPILE_PREBUILT
#include "offsets.h"
#endif

#ifdef COMPILE_RUNTIME
#include <net/flow.h>
#endif

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of part saddr_l and daddr_l.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
// On older kernels, clang can generate Wunused-function warnings on static inline functions defined in
// header files, even if they are later used in source files. __maybe_unused prevents that issue
__maybe_unused static __always_inline bool is_ipv4_mapped_ipv6(__u64 saddr_h, __u64 saddr_l, __u64 daddr_h, __u64 daddr_l) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((saddr_h == 0 && ((__u32)saddr_l == 0xFFFF0000)) || (daddr_h == 0 && ((__u32)daddr_l == 0xFFFF0000)));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((saddr_h == 0 && ((__u32)(saddr_l >> 32) == 0x0000FFFF)) || (daddr_h == 0 && ((__u32)(daddr_l >> 32) == 0x0000FFFF)));
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
}

static __always_inline void read_in6_addr(u64 *addr_h, u64 *addr_l, const struct in6_addr *in6) {
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(addr_h, sizeof(u64), (void *)&(in6->in6_u.u6_addr32[0]));
    bpf_probe_read_kernel_with_telemetry(addr_l, sizeof(u64), (void *)&(in6->in6_u.u6_addr32[2]));
#else
    BPF_CORE_READ_INTO(addr_h, in6, in6_u.u6_addr32[0]);
    BPF_CORE_READ_INTO(addr_l, in6, in6_u.u6_addr32[2]);
#endif
}

static __maybe_unused __always_inline bool is_ipv6_enabled() {
#ifdef COMPILE_RUNTIME
#ifdef FEATURE_IPV6_ENABLED
    return true;
#else
    return false;
#endif
#else
    __u64 val = 0;
    LOAD_CONSTANT("ipv6_enabled", val);
    return val == ENABLED;
#endif
}

static __always_inline int read_conn_tuple_partial_from_flowi6(conn_tuple_t *t, struct flowi6 *fl6, u64 pid_tgid, metadata_mask_t type) {
#if defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    t->pid = pid_tgid >> 32;
    t->metadata = type;

    struct in6_addr addr = BPF_CORE_READ(fl6, saddr);
    if (t->saddr_l == 0 || t->saddr_h == 0) {
        read_in6_addr(&t->saddr_h, &t->saddr_l, &addr);
    }
    if (t->daddr_l == 0 || t->daddr_h == 0) {
        addr = BPF_CORE_READ(fl6, daddr);
        read_in6_addr(&t->daddr_h, &t->daddr_l, &addr);
    }

    if (!(t->saddr_h || t->saddr_l)) {
        log_debug("ERR(fl6): src addr not set src_l:%llx,src_h:%llx\n", t->saddr_l, t->saddr_h);
        return 0;
    }
    if (!(t->daddr_h || t->daddr_l)) {
        log_debug("ERR(fl6): dst addr not set dst_l:%llx,dst_h:%llx\n", t->daddr_l, t->daddr_h);
        return 0;
    }

    // Check if we can map IPv6 to IPv4
    if (is_ipv4_mapped_ipv6(t->saddr_h, t->saddr_l, t->daddr_h, t->daddr_l)) {
        t->metadata |= CONN_V4;
        t->saddr_h = 0;
        t->daddr_h = 0;
        t->saddr_l = (u32)(t->saddr_l >> 32);
        t->daddr_l = (u32)(t->daddr_l >> 32);
    } else {
        t->metadata |= CONN_V6;
    }

    if (t->sport == 0) {
        t->sport = BPF_CORE_READ(fl6, fl6_sport);
        t->sport = bpf_ntohs(t->sport);
    }
    if (t->dport == 0) {
        t->dport = BPF_CORE_READ(fl6, fl6_dport);
        t->dport = bpf_ntohs(t->dport);
    }

    if (t->sport == 0 || t->dport == 0) {
        log_debug("ERR(fl6): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
        return 0;
    }

    return 1;
#elif defined(COMPILE_PREBUILT)
    t->pid = pid_tgid >> 32;
    t->metadata = type;

    if (t->saddr_l == 0 || t->saddr_h == 0) {
        if (!are_fl6_offsets_known()) {
            goto no_offsets;
        }
        read_in6_addr(&t->saddr_h, &t->saddr_l, (struct in6_addr *)(((char *)fl6) + offset_saddr_fl6()));
    }
    if (t->daddr_l == 0 || t->daddr_h == 0) {
        if (!are_fl6_offsets_known()) {
            goto no_offsets;
        }
        read_in6_addr(&t->daddr_h, &t->daddr_l, (struct in6_addr *)(((char *)fl6) + offset_daddr_fl6()));
    }

    if (!(t->saddr_h || t->saddr_l)) {
        log_debug("ERR(fl6): src addr not set src_l:%llx,src_h:%llx\n", t->saddr_l, t->saddr_h);
        return 0;
    }
    if (!(t->daddr_h || t->daddr_l)) {
        log_debug("ERR(fl6): dst addr not set dst_l:%llx,dst_h:%llx\n", t->daddr_l, t->daddr_h);
        return 0;
    }

    // Check if we can map IPv6 to IPv4
    if (is_ipv4_mapped_ipv6(t->saddr_h, t->saddr_l, t->daddr_h, t->daddr_l)) {
        t->metadata |= CONN_V4;
        t->saddr_h = 0;
        t->daddr_h = 0;
        t->saddr_l = (u32)(t->saddr_l >> 32);
        t->daddr_l = (u32)(t->daddr_l >> 32);
    } else {
        t->metadata |= CONN_V6;
    }

    if (t->sport == 0) {
        if (!are_fl6_offsets_known()) {
            goto no_offsets;
        }
        bpf_probe_read_kernel_with_telemetry(&t->sport, sizeof(t->sport), ((char *)fl6) + offset_sport_fl6());
        t->sport = bpf_ntohs(t->sport);
    }
    if (t->dport == 0) {
        if (!are_fl6_offsets_known()) {
            goto no_offsets;
        }
        bpf_probe_read_kernel_with_telemetry(&t->dport, sizeof(t->dport), ((char *)fl6) + offset_dport_fl6());
        t->dport = bpf_ntohs(t->dport);
    }

    if (t->sport == 0 || t->dport == 0) {
        log_debug("ERR(fl6): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
        return 0;
    }

    return 1;

no_offsets:
    log_debug("ERR(fl6): offsets are not known\n");
    return 0;

#endif
}

#endif
