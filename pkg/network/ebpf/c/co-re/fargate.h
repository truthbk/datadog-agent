#ifndef __FARGATE_H__
#define __FARGATE_H__

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers_new.h"
#include "bpf_endian.h"
#include "common.h"
#include "fargate-types.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, tuple_t);
	__type(value, conn_stats_t);
} conn_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, tuple_t);
	__type(value, tcp_stats_t);
} tcp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct sock *);
	__type(value, u32);
} sock_to_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} closed_conns SEC(".maps");

//static __always_inline tcp_flow_stats_t *get_tcp_stats(tuple_t *t) {
//    return bpf_map_lookup_elem(&tcp_stats, t);
//}

static __always_inline tcp_stats_t *upsert_tcp_stats(tuple_t *t) {
    tcp_stats_t stats = {};
    bpf_map_update_elem(&tcp_stats, t, &stats, BPF_NOEXIST);
    return bpf_map_lookup_elem(&tcp_stats, t);
}

//static __always_inline conn_stats_t* get_conn_stats(tuple_t *t) {
//    return bpf_map_lookup_elem(&conn_stats, t);
//}

static __always_inline conn_stats_t* upsert_conn_stats(tuple_t *t) {
    conn_stats_t empty = {};
    long ret = bpf_map_update_elem(&conn_stats, t, &empty, BPF_NOEXIST);
    if (ret == -E2BIG) {
        //increment_telemetry_count(conn_stats_max_entries_hit);
        return NULL;
    }
    return bpf_map_lookup_elem(&conn_stats, t);
}

static __always_inline void add_sent_bytes(tuple_t *t, conn_stats_t *cs, u16 sent_bytes) {
    if (sent_bytes == 0) {
        return;
    }
    __sync_fetch_and_add(&cs->sent_bytes, sent_bytes);
    log_debug("send total: %llu", cs->sent_bytes);
    if (t->protocol != IPPROTO_UDP) {
        return;
    }
    //_update_udp_conn_state(cs, sent_bytes, 0);
}

static __always_inline void add_sent_packets(conn_stats_t *cs, u32 sent_packets) {
    if (sent_packets == 0) {
        return;
    }
    __sync_fetch_and_add(&cs->sent_packets, sent_packets);
}

static __always_inline void add_recv_bytes(tuple_t *t, conn_stats_t *cs, u16 recv_bytes) {
    if (recv_bytes == 0) {
        return;
    }
    __sync_fetch_and_add(&cs->recv_bytes, recv_bytes);
    log_debug("recv total: %llu", cs->recv_bytes);
    if (t->protocol != IPPROTO_UDP) {
        return;
    }
    //_update_udp_conn_state(cs, 0, recv_bytes);
}

static __always_inline void add_recv_packets(conn_stats_t *cs, u32 recv_packets) {
    if (recv_packets == 0) {
        return;
    }
    __sync_fetch_and_add(&cs->recv_packets, recv_packets);
}

static __always_inline void add_retransmits(tcp_stats_t *ts, u32 segs) {
    if (segs == 0) {
        return;
    }
    __sync_fetch_and_add(&ts->retransmits, segs);
}

static __always_inline void set_direction(conn_stats_t *cs, conn_direction_t dir) {
    cs->direction = dir;
}

static __always_inline void flip_tuple(tuple_t *t) {
    struct in6_addr tmp = t->saddr;
    t->saddr = t->daddr;
    t->daddr = tmp;

    u16 tmp_port = t->sport;
    t->sport = t->dport;
    t->dport = tmp_port;
}

static __always_inline u32 pid_from_sock(struct sock *sk) {
    if (!sk) {
        return 0;
    }
//    struct socket *sock = BPF_CORE_READ(sk, sk_socket);
//    log_debug("socket: %x", sock);
//    struct file *f = BPF_CORE_READ(sock, file);
//    log_debug("file: %x", f);
//    struct pid *p = BPF_CORE_READ(f, f_owner.pid);
//    log_debug("pid: %x", p);
//    u32 pid = BPF_CORE_READ(p, numbers[0].nr);
//    log_debug("pid_nr: %d", pid);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return pid;
}

static __always_inline void print_tuple(tuple_t *t) {
#ifdef DEBUG
    static const char tcp_prot[] = "TCP";
    static const char udp_prot[] = "UDP";
    const char *prot = t->protocol == IPPROTO_TCP ? tcp_prot : udp_prot;

    switch (t->family) {
    case AF_INET:
        log_debug("%s %pI4:%d <->", prot, &t->saddr.in6_u.u6_addr32[0], t->sport);
        log_debug("    %pI4:%d", &t->daddr.in6_u.u6_addr32[0], t->dport);
        break;
    case AF_INET6:
        log_debug("%s %pI6:%d <->", prot, &t->saddr, t->sport);
        log_debug("    %pI6:%d", &t->daddr, t->dport);
        break;
    }
#endif
}

static __always_inline bool sock_to_tuple(struct sock *sk, tuple_t *tup) {
    tup->protocol = BPF_CORE_READ(sk, sk_protocol);
    tup->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (tup->family) {
    case AF_INET:
        tup->saddr.in6_u.u6_addr32[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        tup->daddr.in6_u.u6_addr32[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        break;
    case AF_INET6:
        tup->saddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        tup->daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        break;
    default:
        return false;
    }

    tup->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (tup->sport == 0) {
        struct inet_sock *inet_sk = (struct inet_sock *)sk;
        tup->sport = BPF_CORE_READ(inet_sk, inet_sport);
    }
    tup->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    return true;
}

// returns the data length of the skb or a negative value in case of an error
static __always_inline s32 sk_buff_to_tuple(struct sk_buff *skb, tuple_t *tup, skb_info_t *skb_info) {
    u32 trans_len = 0;

    unsigned char *skb_head = BPF_CORE_READ(skb, head);
    u16 net_off = BPF_CORE_READ(skb, network_header);
    u16 trans_off = BPF_CORE_READ(skb, transport_header);

    struct iphdr *tmp_iph = (struct iphdr *)(skb_head + net_off);
    u8 ip_ver = 0;
    bpf_probe_read_kernel(&ip_ver, sizeof(u8), tmp_iph);
    ip_ver = ip_ver >> 4;

    switch (ip_ver) {
    case 4: {
        struct iphdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), tmp_iph);

        tup->family = AF_INET;
        tup->protocol = iph.protocol;
        tup->saddr.in6_u.u6_addr32[0] = iph.saddr;
        tup->daddr.in6_u.u6_addr32[0] = iph.daddr;

        u64 ihl_len = iph.ihl * 4;
        trans_len = bpf_ntohs(iph.tot_len) - ihl_len;
        break;
        }
    case 6: {
        struct ipv6hdr ip6h;
        bpf_probe_read_kernel(&ip6h, sizeof(ip6h), tmp_iph);

        tup->family = AF_INET6;
        tup->protocol = ip6h.nexthdr;
        tup->saddr = ip6h.saddr;
        tup->daddr = ip6h.daddr;

        trans_len = bpf_ntohs(ip6h.payload_len) - sizeof(ip6h);
        break;
        }
    default:
        return -1;
    }

    switch (tup->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr tcp;
        bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_off);
        tup->sport = bpf_ntohs(tcp.source);
        tup->dport = bpf_ntohs(tcp.dest);

        if (skb_info != NULL) {
            bpf_probe_read_kernel(&skb_info->tcp_flags, sizeof(u16), ((void *)&tcp) + TCP_FLAGS_OFFSET);
        }
        return trans_len - (tcp.doff * 4);
        }
    case IPPROTO_UDP: {
        struct udphdr udp;
        bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_off);
        tup->sport = bpf_ntohs(udp.source);
        tup->dport = bpf_ntohs(udp.dest);
        return (u16)(bpf_ntohs(udp.len) - sizeof(udp));
        }
    default:
        return -1;
    }
    return -1;
}

static __always_inline void infer_direction(tuple_t *t, conn_stats_t *cs, skb_info_t *skb_info) {
    if (t->protocol != IPPROTO_TCP || skb_info == NULL || cs->direction != CONN_DIRECTION_UNKNOWN) {
        return;
    }
    if (skb_info->tcp_flags & TCPHDR_SYN) {
        if (skb_info->tcp_flags & TCPHDR_ACK) {
            set_direction(cs, CONN_DIRECTION_INCOMING);
        } else {
            set_direction(cs, CONN_DIRECTION_OUTGOING);
        }
    }
}

#endif
