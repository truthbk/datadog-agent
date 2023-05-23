#ifndef __ISTIO_H
#define __ISTIO_H

#include "ktypes.h"
#include "netns.h"
#include "conn_tuple.h"
#include "ip.h"
#include "conntrack/maps.h"

#ifndef COMPILE_CORE
#include <linux/skbuff.h>
#endif

BPF_HASH_MAP(pid_tgid_to_skb, u64, struct sk_buff *, 1024)
BPF_HASH_MAP(skb_to_netns, struct sk_buff *, u32, 1024)

SEC("kprobe/sk_filter_trim_cap")
int kprobe__sk_filter_trim_cap(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    u32 netns = get_netns_from_sock(sk);

    /* log_debug("pedro: !!! creating mapping for skb=%p", skb); */
    bpf_map_update_elem(&pid_tgid_to_skb, &pid_tgid, &skb, BPF_ANY);
    bpf_map_update_elem(&skb_to_netns, &skb, &netns, BPF_ANY);
    return 0;
}

SEC("kretprobe/sk_filter_trim_cap")
int kretprobe__sk_filter_trim_cap(struct pt_regs* ctx) {
    /* u64 pid_tgid = bpf_get_current_pid_tgid(); */
    /* struct sk_buff **result = bpf_map_lookup_elem(&pid_tgid_to_skb, &pid_tgid); */
    /* if (!result) { */
    /*     return 0; */
    /* } */

    /* struct sk_buff *skb = *result; */
    /* bpf_map_delete_elem(&pid_tgid_to_skb, &pid_tgid); */
    /* if (!skb) { */
    /*     return 0; */
    /* } */

    /* bpf_map_delete_elem(&skb_to_netns, &skb); */
    return 0;
}

static __always_inline void translate_tuple(struct __sk_buff *skb, conn_tuple_t *tuple) {
    if (!tuple) {
        return;
    }

    conntrack_tuple_t ct = {0};
    ct.saddr_h = tuple->saddr_h;
    ct.saddr_l = tuple->saddr_l;
    ct.daddr_h = tuple->daddr_h;
    ct.daddr_l = tuple->daddr_l;
    ct.sport = tuple->sport;
    ct.dport = tuple->dport;
    ct.metadata = tuple->metadata;

    struct sk_buff* skb_kernel = (struct sk_buff*)skb;
    u32 *netns_ptr = bpf_map_lookup_elem(&skb_to_netns, &skb_kernel);
    if (!netns_ptr) {
        log_debug("http: failed to obtain namespace for skb=%p", skb);
        return;
    }

    ct.netns = *netns_ptr;

    log_debug("http: looking for translation for src_ip=%pI4 dst_ip=%pI4 netns=%u", &(tuple->saddr_l), &(tuple->daddr_l), ct.netns);
    conntrack_tuple_t *translated_tuple = bpf_map_lookup_elem(&conntrack, &ct);
    bool flipped = false;
    if (!translated_tuple) {
        flipped = true;
        flip_tuple((conn_tuple_t *)&ct);
        translated_tuple = bpf_map_lookup_elem(&conntrack, &ct);

    }

    if (!translated_tuple) {
        log_debug("http: could *not* find translation for src_ip=%pI4 dst_ip=%pI4 metadata=%u", &(ct.saddr_l), &(ct.daddr_l), ct.metadata);
        return;
    }

    log_debug("http: fetched translation for src_ip=%pI4 dst_ip=%pI4 pkg_mark=%lu", &(tuple->saddr_l), &(tuple->daddr_l), skb->mark);
    log_debug("http: translation is src_ip=%pI4 dst_ip=%pI4", &translated_tuple->saddr_l, &translated_tuple->daddr_l);
    tuple->saddr_h = translated_tuple->saddr_h;
    tuple->saddr_l = translated_tuple->saddr_l;
    tuple->daddr_h = translated_tuple->daddr_h;
    tuple->daddr_l = translated_tuple->daddr_l;
    tuple->sport = translated_tuple->sport;
    tuple->dport = translated_tuple->dport;
    if (flipped) {
        flip_tuple(tuple);
    }
}

#endif
