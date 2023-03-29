#ifndef __NETNS_H
#define __NETNS_H

#include "bpf_core_read.h"
#include "bpf_telemetry.h"

#ifdef COMPILE_RUNTIME
#include <net/net_namespace.h>
#include <net/sock.h>
#endif

#ifdef COMPILE_CORE
#define sk_net __sk_common.skc_net
#define CONFIG_NET_NS
#endif

#ifdef COMPILE_PREBUILT

static __always_inline __u32 get_netns_from_sock(struct sock* sk) {
    void* skc_net = NULL;
    __u32 net_ns_inum = 0;
    bpf_probe_read_kernel_with_telemetry(&skc_net, sizeof(void*), ((char*)sk) + offset_netns());
    bpf_probe_read_kernel_with_telemetry(&net_ns_inum, sizeof(net_ns_inum), ((char*)skc_net) + offset_ino());
    return net_ns_inum;
}

#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)

static __always_inline u32 get_netns_ino(struct net* ns) {
    u32 net_ns_inum = 0;
#if !defined(COMPILE_RUNTIME) || defined(CONFIG_NET_NS)
#if defined(_LINUX_NS_COMMON_H) || defined(COMPILE_CORE)
    BPF_CORE_READ_INTO(&net_ns_inum, ns, ns.inum);
#else
    BPF_CORE_READ_INTO(&net_ns_inum, ns, proc_inum);
#endif
#endif
    return net_ns_inum;
}

struct sock_common___old {
    struct net *skc_net;
};

struct net___old {
    unsigned int proc_inum;
};

struct sock___old {
    struct sock_common___old __sk_common;
};

static __maybe_unused __always_inline u32 get_netns_from_sock(struct sock *sk) {
    // Retrieve network namespace id
    //
    // `possible_net_t skc_net`
    // replaced
    // `struct net *skc_net`
    // https://github.com/torvalds/linux/commit/0c5c9fb55106333e773de8c9dd321fa8240caeb3
    u32 net_ns_inum = 0;
#if defined(COMPILE_RUNTIME) && defined(CONFIG_NET_NS)
#if defined(_LINUX_NS_COMMON_H)
    BPF_PROBE_READ_INTO(&net_ns_inum, sk, sk_net.net, ns.inum);
#else
    BPF_CORE_READ_INTO(&net_ns_inum, sk, sk_net, proc_inum);
#endif // LINUX_NS_COMMON_H
#elif defined(COMPILE_CORE)
    if (bpf_core_field_exists(sk->__sk_common.skc_net.net)) {
        BPF_CORE_READ_INTO(&net_ns_inum, sk, sk_net.net, ns.inum);
    } else {
        struct sock___old *oldsk = (struct sock___old *)sk;

        // inum wrapped in ns_common
        // https://github.com/torvalds/linux/commit/435d5f4bb2ccba3b791d9ef61d2590e30b8e806e
        if (bpf_core_field_exists(oldsk->sk_net->ns)) {
            BPF_CORE_READ_INTO(&net_ns_inum, oldsk, sk_net, ns.inum);
        } else {
            struct net___old *oldnet = 0;
            BPF_CORE_READ_INTO(&oldnet, oldsk, sk_net);
            BPF_CORE_READ_INTO(&net_ns_inum, oldnet, proc_inum);
        }
    }
#endif

    return net_ns_inum;
}

// depending on the kernel version p_net may be a struct net** or possible_net_t*
__maybe_unused static __always_inline u32 get_netns(void *p_net) {
    struct net *ns = NULL;
#if !defined(COMPILE_RUNTIME) || defined(CONFIG_NET_NS)
    bpf_probe_read_kernel_with_telemetry(&ns, sizeof(ns), p_net);
#endif
    return get_netns_ino(ns);
}

#endif // COMPILE_CORE || COMPILE_PREBUILT

#endif
