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

#define ENVOY_OUTBOUND_PORT 15001
#define ENVOY_INBOUND_PORT 15006

struct sk_history {
    struct sock *curr;
    struct sock *prev;
};

struct {
    struct sk_history read;
    struct sk_history write;
} typedef envoy_thread_monitor_t;

typedef enum {
    SOCK_OP_UNKNOWN = 0,
    SOCK_OP_READ,
    SOCK_OP_WRITE,
} sock_op_t;

BPF_HASH_MAP(pid_tgid_to_skb, u64, struct sk_buff *, 1024)
BPF_HASH_MAP(skb_to_netns, struct sk_buff *, u32, 1024)
BPF_HASH_MAP(envoy_thread_monitors, u64, envoy_thread_monitor_t, 1024)
BPF_HASH_MAP(envoy_plain_to_encrypted, conn_tuple_t, conn_tuple_t, 1024)

static __always_inline envoy_thread_monitor_t* fetch_envoy_thread_monitor(struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    envoy_thread_monitor_t *etm = bpf_map_lookup_elem(&envoy_thread_monitors, &pid_tgid);
    if (etm) {
        // If this pid_tgid has matched a map entry, it means we're dealing with
        // an Envoy worker thread responsible for managing traffic related to
        // the application container
        return etm;
    }

    // Else we take a look at the socket we're dealing with. If the source port
    // matches the Istio port, we have a new envoy worker thread, and therefore we
    // create a map entry to track socket activity for this particular thread.
    conn_tuple_t tuple;
    if (!read_conn_tuple(&tuple, sk, pid_tgid, CONN_TYPE_TCP)) {
        return NULL;
    }

    if (tuple.sport != ENVOY_OUTBOUND_PORT && tuple.sport != ENVOY_OUTBOUND_PORT) {
        return NULL;
    }

    envoy_thread_monitor_t empty;
    bpf_memset(&empty, 0, sizeof(empty));
    bpf_map_update_elem(&envoy_thread_monitors, &pid_tgid, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&envoy_thread_monitors, &pid_tgid);
}

static __always_inline void update_sk_history(struct sk_history *history, struct sock *sk) {
    // If the previous socket operation was of the same type was done over the
    // same socket, don't do anything.
    if (history->curr == sk) {
        return;
    }

    history->prev = history->curr;
    history->curr = sk;
}

// This function returns true when the network traffic managed by a certain
// envoy thread satisfy the heuristic described above. The "link" represents the
// association between two sockets belonging to an envoy sidecar: One that
// handles plain traffic and which communicates with the application container,
// and the another one that handles encrypted traffic and which communicates
// with the "outside".
static __always_inline bool envoy_can_link_traffic(envoy_thread_monitor_t *etm) {
    return (etm->read.curr &&
            etm->read.prev &&
            etm->write.curr &&
            etm->write.prev &&
            etm->read.curr != etm->write.curr &&
            etm->read.curr == etm->write.prev &&
            etm->read.prev == etm->write.curr);
}

static __always_inline bool envoy_get_socket_tuples(envoy_thread_monitor_t *etm, conn_tuple_t *t1, conn_tuple_t *t2) {
    if (!read_conn_tuple(t1, etm->read.curr, 0, CONN_TYPE_TCP)) {
        return false;
    }
    if (!read_conn_tuple(t2, etm->write.curr, 0, CONN_TYPE_TCP)) {
        return false;
    }

    t1->pid = 0;
    t1->netns = 0;
    t2->pid = 0;
    t2->netns = 0;

    return true;
}

static __always_inline void envoy_create_mapping(envoy_thread_monitor_t *etm) {
    conn_tuple_t t1;
    conn_tuple_t t2;
    if (!envoy_get_socket_tuples(etm, &t1, &t2)) {
        return;
    }

    conn_tuple_t *plain = &t1;
    conn_tuple_t *encrypted = &t2;
    if (encrypted->sport == ENVOY_OUTBOUND_PORT || plain->sport == ENVOY_INBOUND_PORT) {
        plain = &t2;
        encrypted = &t1;
    }

    normalize_tuple(plain);
    normalize_tuple(encrypted);
    log_debug("istio: plain_traffic: %pI4 -> %pI4\n", &plain->saddr_l, &plain->daddr_l);
    log_debug("istio: encrypted_traffic: %pI4 -> %pI4\n", &encrypted->saddr_l, &encrypted->daddr_l);
    bpf_map_update_elem(&envoy_plain_to_encrypted, plain, encrypted, BPF_NOEXIST);
}

static __always_inline void update_monitor_information(envoy_thread_monitor_t *etm, struct sock *sk, sock_op_t op) {
    // Save the socket pointer address that is currently executing a read or
    // write operation for this particular Envoy worker thread
    switch(op) {
    case SOCK_OP_READ:
        update_sk_history(&etm->read, sk);
        break;
    case SOCK_OP_WRITE:
        update_sk_history(&etm->write, sk);
        break;
    default:
        return;
    }

    // Attempt to determine whether the traffic pattern we're seeing allows us
    // to establish a link between plain and encrypted traffic
    if (!envoy_can_link_traffic(etm)) {
        return;
    }

    envoy_create_mapping(etm);
}

static __always_inline void istio_process(struct sock *sk, sock_op_t op) {
    envoy_thread_monitor_t *etm = fetch_envoy_thread_monitor(sk);
    if (!etm) {
        return;
    }

    update_monitor_information(etm, sk, op);
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
