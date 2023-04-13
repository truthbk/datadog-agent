#include "ktypes.h"
#include "bpf_tracing.h"
#include "bpf_telemetry.h"
#include "bpf_endian.h"

#include "conntrack.h"
#include "conntrack-maps.h"
#include "netns.h"
#include "ip.h"
#include "ipv6.h"

SEC("kprobe/__nf_conntrack_hash_insert")
int BPF_KPROBE(kprobe___nf_conntrack_hash_insert, struct nf_conn *ct) {
    u32 status = BPF_CORE_READ(ct, status);
    if (!(status&IPS_CONFIRMED) || !(status&IPS_NAT_MASK)) {
        return 0;
    }

    log_debug("kprobe/__nf_conntrack_hash_insert: netns: %u, status: %x\n", get_netns(&ct->ct_net), status);

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }

    bpf_map_update_with_telemetry(conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_with_telemetry(conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

SEC("kprobe/ctnetlink_fill_info")
int BPF_KPROBE(kprobe_ctnetlink_fill_info, struct sk_buff *skb, u32 portid, u32 seq, u32 type, struct nf_conn *ct) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != systemprobe_pid()) {
        log_debug("skipping kprobe/ctnetlink_fill_info invocation from non-system-probe process\n");
        return 0;
    }

    u32 status = BPF_CORE_READ(ct, status);
    if (!(status&IPS_CONFIRMED) || !(status&IPS_NAT_MASK)) {
        return 0;
    }

    log_debug("kprobe/ctnetlink_fill_info: netns: %u, status: %x\n", get_netns(&ct->ct_net), status);

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }

    bpf_map_update_with_telemetry(conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_with_telemetry(conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";
