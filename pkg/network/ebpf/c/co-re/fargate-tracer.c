#include "fargate.h"
#include "bpf_tracing.h"

char _license[] SEC("license") = "GPL";

SEC("raw_tp/netif_receive_skb")
int BPF_PROG(trace_netif_receive_skb, struct sk_buff *skb) {
    tuple_t t = {};
    skb_info_t skb_info = {};
    s32 recv_count = sk_buff_to_tuple(skb, &t, &skb_info);
    if (recv_count <= 0) {
        return 0;
    }

    flip_tuple(&t);
#ifdef DEBUG
    struct sock *sk = BPF_CORE_READ(skb, sk);
    log_debug("netif_receive_skb: sk=%llx len=%d", sk, recv_count);
    print_tuple(&t);
#endif

    conn_stats_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    add_recv_bytes(&t, cs, recv_count);
    add_recv_packets(cs, 1);
    infer_direction(&t, cs, &skb_info);
    return 0;
}

SEC("raw_tp/net_dev_queue")
int BPF_PROG(trace_net_dev_queue, struct sk_buff *skb) {
    tuple_t t = {};
    skb_info_t skb_info = {};
    s32 sent_count = sk_buff_to_tuple(skb, &t, &skb_info);
    if (sent_count < 0) {
        return 0;
    }

#ifdef DEBUG
    struct sock *sk = BPF_CORE_READ(skb, sk);
    log_debug("net_dev_queue: sk=%llx len=%d", sk, sent_count);
    print_tuple(&t);
#endif

    conn_stats_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    add_sent_bytes(&t, cs, sent_count);
    add_sent_packets(cs, 1);
    infer_direction(&t, cs, &skb_info);
    if (!cs->pid) {
        cs->pid = bpf_get_current_pid_tgid() >> 32;
    }
    if (t.protocol == IPPROTO_TCP) {
        struct sock *sk = BPF_CORE_READ(skb, sk);
        if (sk) {
            struct tcp_sock *tcp_sk = (struct tcp_sock *)sk;
            tcp_stats_t *ts = upsert_tcp_stats(&t);
            if (ts) {
                ts->rtt = BPF_CORE_READ(tcp_sk, srtt_us) >> 3;
                ts->rtt_var = BPF_CORE_READ(tcp_sk, mdev_us) >> 2;
            }
        }
    }
    return 0;
}

SEC("raw_tp/tcp_retransmit_skb")
int BPF_PROG(trace_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb) {
    tuple_t t = {};
    if (!sock_to_tuple(sk, &t)) {
        return 0;
    }

    struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)BPF_CORE_READ(skb, cb);
    u32 segs = BPF_CORE_READ(tcb, tcp_gso_segs);
    log_debug("tcp_retransmit_skb: sk=%llx segs=%d", sk, segs);
    print_tuple(&t);

    tcp_stats_t *ts = upsert_tcp_stats(&t);
    if (ts == NULL) {
        return 0;
    }
    add_retransmits(ts, segs);
    return 0;
}

SEC("raw_tp/inet_sock_set_state")
int BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate, int newstate) {
    if (newstate != BPF_TCP_ESTABLISHED &&
        newstate != BPF_TCP_CLOSE) {
        return 0;
    }
    tuple_t t = {};
    if (!sock_to_tuple(sk, &t)) {
        return 0;
    }
    log_debug("inet_sock_set_state: sk=%llx", sk);
    print_tuple(&t);

    switch (newstate) {
    case BPF_TCP_ESTABLISHED: {
        if (t.protocol != IPPROTO_TCP) {
            return 0;
        }
        tcp_stats_t *ts = upsert_tcp_stats(&t);
        if (!ts) {
            return 0;
        }
        ts->state_transitions |= (1 << newstate);
        return 0;
        }
    case BPF_TCP_CLOSE: {
        conn_stats_t *cs = bpf_map_lookup_elem(&conn_stats, &t);
        if (!cs) {
            goto cleanup;
        }
        conn_event_t event = {};
        event.tup = t;
        event.conn_stats = *cs;
        if (t.protocol == IPPROTO_TCP) {
            tcp_stats_t *ts = upsert_tcp_stats(&event.tup);
            if (!ts) {
                goto cleanup;
            }
            ts->state_transitions |= (1 << newstate);
            event.tcp_stats = *ts;
        }
        bpf_ringbuf_output(&closed_conns, &event, sizeof(event), 0);
        break;
        }
    }

cleanup:
    bpf_map_delete_elem(&conn_stats, &t);
    bpf_map_delete_elem(&tcp_stats, &t);
    return 0;
}

