#ifndef __ISTIO_H
#define __ISTIO_H

#include "ktypes.h"
#include "netns.h"
#include "conn_tuple.h"
#include "sock.h"
#include "ip.h"
#include "skb.h"

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

BPF_LRU_MAP(envoy_thread_monitors, u64, envoy_thread_monitor_t, 1024)
BPF_LRU_MAP(envoy_plain_to_encrypted, conn_tuple_t, conn_tuple_t, 1024)
BPF_LRU_MAP(envoy_nat_translations, conn_tuple_t, conn_tuple_t, 1024)

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
    log_debug("istio: plain_traffic(1): from %pI4:%u", &plain->saddr_l, plain->sport);
    log_debug("istio: plain_traffic(2): to %pI4:%u", &plain->daddr_l, plain->dport);
    log_debug("istio: encrypted_traffic(1): from %pI4:%u", &encrypted->saddr_l, encrypted->sport);
    log_debug("istio: encrypted_traffic(2): to %pI4:%u", &encrypted->daddr_l, encrypted->dport);
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

static __always_inline void istio_translate_tuple(conn_tuple_t *normalized_tuple) {
    conn_tuple_t *t = bpf_map_lookup_elem(&envoy_nat_translations, normalized_tuple);
    if (!t) {
        return;
    }
    *normalized_tuple = *t;
}

static __always_inline void istio_replace_tuple(conn_tuple_t *normalized_tuple) {
    // lookup key must be in the stack for older kernels
    conn_tuple_t key = *normalized_tuple;

    conn_tuple_t *t = bpf_map_lookup_elem(&envoy_plain_to_encrypted, &key);
    if (!t) {
        if (normalized_tuple->dport == ENVOY_OUTBOUND_PORT || normalized_tuple->dport == ENVOY_INBOUND_PORT) {
            log_debug("istio: error: couldn't find tuple for %pI4:%u", &(normalized_tuple->saddr_l), normalized_tuple->sport);
        }
        return;
    }
    *normalized_tuple = *t;
}

// Represents the parameters being passed to the tracepoint net/net_dev_queue
struct net_dev_queue_ctx {
    u64 unused;
    struct sk_buff* skb;
};

static __always_inline struct sock* sk_buff_sk(struct sk_buff *skb) {
    struct sock * sk = NULL;
#ifdef COMPILE_PREBUILT
    bpf_probe_read(&sk, sizeof(struct sock*), (char*)skb + offset_sk_buff_sock());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&sk, skb, sk);
#endif

    return sk;
}

SEC("tracepoint/net/net_dev_queue")
int tracepoint__net__net_dev_queue(struct net_dev_queue_ctx* ctx) {
    struct sk_buff* skb = ctx->skb;
    if (!skb) {
        return 0;
    }
    struct sock* sk = sk_buff_sk(skb);
    if (!sk) {
        return 0;
    }

    conn_tuple_t sock_tup;
    bpf_memset(&sock_tup, 0, sizeof(conn_tuple_t));
    if (!read_conn_tuple(&sock_tup, sk, 0, CONN_TYPE_TCP)) {
        return 0;
    }
    sock_tup.netns = 0;
    sock_tup.pid = 0;

    if (sock_tup.sport != ENVOY_OUTBOUND_PORT && sock_tup.sport != ENVOY_OUTBOUND_PORT) {
        return 0;
    }

    conn_tuple_t skb_tup;
    bpf_memset(&skb_tup, 0, sizeof(conn_tuple_t));
    if (sk_buff_to_tuple(skb, &skb_tup) <= 0) {
        return 0;
    }

    if (!is_equal(&skb_tup, &sock_tup)) {
        normalize_tuple(&skb_tup);
        normalize_tuple(&sock_tup);
        bpf_map_update_elem(&envoy_nat_translations, &skb_tup, &sock_tup, BPF_NOEXIST);
    }

    return 0;
}

#endif
