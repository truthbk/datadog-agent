#include "kconfig.h"
#include <linux/version.h>

#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "conntrack.h"
#include "conntrack-maps.h"
#include "netns.h"
#include "ip.h"

#ifdef FEATURE_IPV6_ENABLED
#include "ipv6.h"
#endif

#ifndef LINUX_VERSION_CODE
# error "kernel version not included?"
#endif

SEC("kprobe/__nf_conntrack_hash_insert")
int BPF_KPROBE(kprobe___nf_conntrack_hash_insert, struct nf_conn *ct) {
    u32 status = ct_status(ct);
    if (!(status&IPS_CONFIRMED) || !(status&IPS_NAT_MASK)) {
        return 0;
    }

    log_debug("kprobe/__nf_conntrack_hash_insert: netns: %u, status: %x\n", get_netns(&ct->ct_net), status);

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }

    bpf_map_update_elem(&conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_elem(&conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

SEC("kprobe/ctnetlink_fill_info")
int BPF_KPROBE(kprobe_ctnetlink_fill_info, struct sk_buff *skb, u32 portid, u32 seq, u32 type, struct nf_conn *ct) {
    proc_t proc = {};
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    if (!proc_t_comm_prefix_equals("system-probe", 12, proc)) {
        log_debug("skipping kprobe/ctnetlink_fill_info invocation from non-system-probe process\n");
        return 0;
    }

    u32 status = ct_status(ct);
    if (!(status&IPS_CONFIRMED) || !(status&IPS_NAT_MASK)) {
        return 0;
    }

    log_debug("kprobe/ctnetlink_fill_info: netns: %u, status: %x\n", get_netns(&ct->ct_net), status);

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }

    bpf_map_update_elem(&conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_elem(&conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
