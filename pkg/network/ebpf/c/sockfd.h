#ifndef __SOCKFD_H
#define __SOCKFD_H

#include "bpf_builtins.h"
#include "tracer.h"
#include <linux/types.h>
#include <net/inet_sock.h>

// This map is used to to temporarily store function arguments (sockfd) for
// sockfd_lookup_light function calls, so they can be accessed by the corresponding kretprobe.
// * Key is the pid_tgid;
// * Value the socket FD;
BPF_HASH_MAP(sockfd_lookup_args, __u64, __u32, 1024)

BPF_HASH_MAP(sock_by_pid_fd, pid_fd_t, struct sock *, 1024)
    
BPF_HASH_MAP(pid_fd_by_sock, struct sock *, pid_fd_t, 1024)
    
// On older kernels, clang can generate Wunused-function warnings on static inline functions defined in 
// header files, even if they are later used in source files. __maybe_unused prevents that issue
__maybe_unused static __always_inline void clear_sockfd_maps(struct sock* sock) {
    if (sock == NULL) {
        return;
    }

    pid_fd_t* pid_fd = bpf_map_lookup_elem(&pid_fd_by_sock, &sock);
    if (pid_fd == NULL) {
        return;
    }

    // Copy map value to stack before re-using it (needed for Kernel 4.4)
    pid_fd_t pid_fd_copy = {};
    bpf_memcpy(&pid_fd_copy, pid_fd, sizeof(pid_fd_t));
    pid_fd = &pid_fd_copy;

    bpf_map_delete_elem(&sock_by_pid_fd, pid_fd);
    bpf_map_delete_elem(&pid_fd_by_sock, &sock);
}

static __always_inline __u64 offset_socket_sk();

SEC("kprobe/sockfd_lookup_light")
int kprobe__sockfd_lookup_light(struct pt_regs* ctx) {
    int sockfd = (int)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Check if have already a map entry for this pid_fd_t
    // TODO: This lookup eliminates *4* map operations for existing entries
    // but can reduce the accuracy of programs relying on socket FDs for
    // processes with a lot of FD churn
    pid_fd_t key = {
        .pid = pid_tgid >> 32,
        .fd = sockfd,
    };
    struct sock** sock = bpf_map_lookup_elem(&sock_by_pid_fd, &key);
    if (sock != NULL) {
        return 0;
    }

    bpf_map_update_elem(&sockfd_lookup_args, &pid_tgid, &sockfd, BPF_ANY);
    return 0;
}

// this kretprobe is essentially creating:
// * an index of pid_fd_t to a struct sock*;
// * an index of struct sock* to pid_fd_t;
SEC("kretprobe/sockfd_lookup_light")
int kretprobe__sockfd_lookup_light(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int *sockfd = bpf_map_lookup_elem(&sockfd_lookup_args, &pid_tgid);
    if (sockfd == NULL) {
        return 0;
    }

    // For now let's only store information for TCP sockets
    struct socket* socket = (struct socket*)PT_REGS_RC(ctx);
    enum sock_type sock_type = 0;
    bpf_probe_read_kernel(&sock_type, sizeof(short), &socket->type);

    // (struct socket).ops is always directly after (struct socket).sk,
    // which is a pointer.
    u64 ops_offset = offset_socket_sk() + sizeof(void*);
    struct proto_ops *proto_ops = NULL;
    bpf_probe_read_kernel(&proto_ops, sizeof(proto_ops), (void*)(socket) + ops_offset);
    if (!proto_ops) {
        goto cleanup;
    }

    int family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &proto_ops->family);
    if (sock_type != SOCK_STREAM || !(family == AF_INET || family == AF_INET6)) {
        goto cleanup;
    }

    // Retrieve struct sock* pointer from struct socket*
    struct sock *sock = NULL;
    bpf_probe_read_kernel(&sock, sizeof(sock), (char*)socket + offset_socket_sk());

    pid_fd_t pid_fd = {
        .pid = pid_tgid >> 32,
        .fd = (*sockfd),
    };

    // These entries are cleaned up by tcp_close
    bpf_map_update_elem(&pid_fd_by_sock, &sock, &pid_fd, BPF_ANY);
    bpf_map_update_elem(&sock_by_pid_fd, &pid_fd, &sock, BPF_ANY);
cleanup:
    bpf_map_delete_elem(&sockfd_lookup_args, &pid_tgid);
    return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs* ctx) {
    struct sock* sk;
    sk = (struct sock*)PT_REGS_PARM1(ctx);
    clear_sockfd_maps(sk);
    return 0;
}

#endif
