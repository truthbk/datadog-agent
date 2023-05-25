#ifndef __ISTIO_H
#define __ISTIO_H

#include "ktypes.h"
#include "netns.h"
#include "conn_tuple.h"
#include "sock.h"
#include "ip.h"
#include "conntrack/maps.h"

#ifndef COMPILE_CORE
#include <linux/skbuff.h>
#endif

#define ISTIO_PORT 15001

struct sk_activity_history {
    void *curr;
    void *prev;
};

struct {
    struct sk_activity_history read_history;
    struct sk_activity_history write_history;
} typedef istio_traffic_t;

BPF_HASH_MAP(pid_tgid_to_skb, u64, struct sk_buff *, 1024)
BPF_HASH_MAP(skb_to_netns, struct sk_buff *, u32, 1024)
BPF_HASH_MAP(traffic_by_worker_thread, u64, istio_traffic_t, 1024)

typedef enum {
    SOCK_OP_UNKNOWN = 0,
    SOCK_OP_READ,
    SOCK_OP_WRITE,
} sock_op_t;

static __always_inline istio_traffic_t* fetch_istio_traffic(struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    istio_traffic_t *it = bpf_map_lookup_elem(&traffic_by_worker_thread, &pid_tgid);
    if (it) {
        return it;
    }

    conn_tuple_t tuple = {};
    if (!read_conn_tuple(&tuple, sk, pid_tgid, CONN_TYPE_TCP)) {
        return NULL;
    }

    if (tuple.sport != ISTIO_PORT && tuple.dport != ISTIO_PORT) {
        return NULL;
    }

    istio_traffic_t empty;
    bpf_memset(&empty, 0, sizeof(empty));
    bpf_map_update_elem(&traffic_by_worker_thread, &pid_tgid, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&traffic_by_worker_thread, &pid_tgid);
}

static __always_inline void update_istio_traffic_inner(struct sk_activity_history *activity_history, struct sock *sk) {
    // if the previous socket operation was of the same type was done over the
    // same socket, don't do anything.
    if (activity_history->curr == sk) {
        return;
    }

    activity_history->prev = activity_history->curr;
    activity_history->curr = (void *)sk;
}

static __always_inline bool complete_history(struct sk_activity_history *activity_history) {
    return activity_history->curr && activity_history->prev;
}

static __always_inline bool istio_can_link_socket_activity(istio_traffic_t *it) {
    if (!complete_history(&it->read_history) || !complete_history(&it->write_history)) {
        // we don't have enough data to run our linking heuristic
        return false;
    }

    return (
            it->read_history.curr != it->write_history.curr &&
            it->read_history.curr == it->write_history.prev &&
            it->read_history.prev == it->write_history.curr);
}

static __always_inline bool istio_get_socket_tuples(istio_traffic_t *it, conn_tuple_t *downstream, conn_tuple_t *upstream) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!read_conn_tuple(downstream, (struct sock*)it->read_history.curr, pid_tgid, CONN_TYPE_TCP)) {
        return false;
    }
    if (!read_conn_tuple(upstream, (struct sock*)it->write_history.curr, pid_tgid, CONN_TYPE_TCP)) {
        return false;
    }
    return true;
}

static __always_inline void update_istio_traffic(istio_traffic_t *it, struct sock *sk, sock_op_t op) {
    switch(op) {
    case SOCK_OP_READ:
        update_istio_traffic_inner(&it->read_history, sk);
        break;
    case SOCK_OP_WRITE:
        update_istio_traffic_inner(&it->write_history, sk);
        break;
    default:
        return;
    }

    if (!istio_can_link_socket_activity(it)) {
        return;
    }

    conn_tuple_t downstream;
    conn_tuple_t upstream;
    if (!istio_get_socket_tuples(it, &downstream, &upstream)) {
        return;
    }

}

static __always_inline void istio_process(struct sock *sk, sock_op_t op) {
    istio_traffic_t *it = fetch_istio_traffic(sk);
    if (!it) {
        return;
    }

    update_istio_traffic(it, sk, op);
}

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
