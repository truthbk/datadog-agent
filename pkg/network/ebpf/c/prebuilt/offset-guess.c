#include "kconfig.h"
#include "offset-guess.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "map-defs.h"

#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/flow.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>

// aligned_offset returns an offset that when added to
// p, would produce an address that is mod size (aligned).
//
// This function works in concert with the offset guessing
// code in pkg/network/tracer/offsetguess.go that will
// increment the returned here by 1 (thus yielding an offset
// that will not produce an aligned address anymore). When
// that offset is passed in here on subsequent calls, it
// has the affect of producing an offset that will move
// p to the next address mod size.
static __always_inline u64 aligned_offset(void *p, u64 offset, uintptr_t size) {
    u64 _p = (u64)p;
    _p += offset;
    // for a value of _p that is not mod size
    // we want to advance to the next _p that is
    // mod size
    _p = _p + size - 1 - (_p + size - 1) % size;
    return (char*)_p - (char*)p;
}

/* These maps are used to match the kprobe & kretprobe of connect for IPv6 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
BPF_HASH_MAP(connectsock_ipv6, __u64, void*, 1024)

BPF_HASH_MAP(tracer_guess, __u64, tracer_guess_t, 1)
BPF_HASH_MAP(conntrack_guess, __u64, conntrack_guess_t, 1)

static __always_inline bool proc_t_comm_equals(proc_t a, proc_t b) {
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (a.comm[i] != b.comm[i]) {
            return false;
        }
        // if chars equal but a NUL terminator, both strings equal
        if (!a.comm[i]) {
            break;
        }
    }
    return true;
}

static __always_inline bool check_family(struct sock* sk, tracer_guess_t* guess, u16 expected_family) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(u16), ((char*)sk) + guess->offsets.family);
    return family == expected_family;
}

static __always_inline int guess_offsets(tracer_guess_t* guess, char* subject) {
    u64 zero = 0;

    if (guess->status.state != STATE_CHECKING) {
        return 1;
    }

    // Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
    // Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
    // with runtime.LockOSThread.
    proc_t proc = {};
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    if (!proc_t_comm_equals(guess->status.proc, proc)) {
        return 0;
    }

    tracer_guess_t new_guess = {};
    // Copy values from status to new_guess
    bpf_probe_read_kernel(&new_guess, sizeof(tracer_guess_t), guess);
    new_guess.status.state = STATE_CHECKED;
    new_guess.status.err = 0;
    bpf_probe_read_kernel(&new_guess.status.proc.comm, sizeof(proc.comm), proc.comm);

    possible_net_t* possible_skc_net = NULL;
    u32 possible_netns = 0;
    long ret;

    switch (guess->status.what) {
    case GUESS_SADDR:
        new_guess.offsets.saddr = aligned_offset(subject, guess->offsets.saddr, SIZEOF_SADDR);
        bpf_probe_read_kernel(&new_guess.values.saddr, sizeof(new_guess.values.saddr), subject + new_guess.offsets.saddr);
        break;
    case GUESS_DADDR:
        new_guess.offsets.daddr = aligned_offset(subject, guess->offsets.daddr, SIZEOF_DADDR);
        bpf_probe_read_kernel(&new_guess.values.daddr, sizeof(new_guess.values.daddr), subject + new_guess.offsets.daddr);
        break;
    case GUESS_FAMILY:
        new_guess.offsets.family = aligned_offset(subject, guess->offsets.family, SIZEOF_FAMILY);
        bpf_probe_read_kernel(&new_guess.values.family, sizeof(new_guess.values.family), subject + new_guess.offsets.family);
        break;
    case GUESS_SPORT:
        new_guess.offsets.sport = aligned_offset(subject, guess->offsets.sport, SIZEOF_SPORT);
        bpf_probe_read_kernel(&new_guess.values.sport, sizeof(new_guess.values.sport), subject + new_guess.offsets.sport);
        new_guess.values.sport = bpf_ntohs(new_guess.values.sport);
        break;
    case GUESS_DPORT:
        new_guess.offsets.dport = aligned_offset(subject, guess->offsets.dport, SIZEOF_DPORT);
        bpf_probe_read_kernel(&new_guess.values.dport, sizeof(new_guess.values.dport), subject + new_guess.offsets.dport);
        new_guess.values.dport = bpf_ntohs(new_guess.values.dport);
        break;
    case GUESS_SADDR_FL4:
        new_guess.offsets.saddr_fl4 = aligned_offset(subject, guess->offsets.saddr_fl4, SIZEOF_SADDR_FL4);
        bpf_probe_read_kernel(&new_guess.values.saddr_fl4, sizeof(new_guess.values.saddr_fl4), subject + new_guess.offsets.saddr_fl4);
        break;
    case GUESS_DADDR_FL4:
        new_guess.offsets.daddr_fl4 = aligned_offset(subject, guess->offsets.daddr_fl4, SIZEOF_DADDR_FL4);
        bpf_probe_read_kernel(&new_guess.values.daddr_fl4, sizeof(new_guess.values.daddr_fl4), subject + new_guess.offsets.daddr_fl4);
        break;
    case GUESS_SPORT_FL4:
        new_guess.offsets.sport_fl4 = aligned_offset(subject, guess->offsets.sport_fl4, SIZEOF_SPORT_FL4);
        bpf_probe_read_kernel(&new_guess.values.sport_fl4, sizeof(new_guess.values.sport_fl4), subject + new_guess.offsets.sport_fl4);
        new_guess.values.sport_fl4 = bpf_ntohs(new_guess.values.sport_fl4);
        break;
    case GUESS_DPORT_FL4:
        new_guess.offsets.dport_fl4 = aligned_offset(subject, guess->offsets.dport_fl4, SIZEOF_DPORT_FL4);
        bpf_probe_read_kernel(&new_guess.values.dport_fl4, sizeof(new_guess.values.dport_fl4), subject + new_guess.offsets.dport_fl4);
        new_guess.values.dport_fl4 = bpf_ntohs(new_guess.values.dport_fl4);
        break;
    case GUESS_SADDR_FL6:
        new_guess.offsets.saddr_fl6 = aligned_offset(subject, guess->offsets.saddr_fl6, SIZEOF_SADDR_FL6);
        bpf_probe_read_kernel(&new_guess.values.saddr_fl6, sizeof(u32) * 4, subject + new_guess.offsets.saddr_fl6);
        break;
    case GUESS_DADDR_FL6:
        new_guess.offsets.daddr_fl6 = aligned_offset(subject, guess->offsets.daddr_fl6, SIZEOF_DADDR_FL6);
        bpf_probe_read_kernel(&new_guess.values.daddr_fl6, sizeof(u32) * 4, subject + new_guess.offsets.daddr_fl6);
        break;
    case GUESS_SPORT_FL6:
        new_guess.offsets.sport_fl6 = aligned_offset(subject, guess->offsets.sport_fl6, SIZEOF_SPORT_FL6);
        bpf_probe_read_kernel(&new_guess.values.sport_fl6, sizeof(new_guess.values.sport_fl6), subject + new_guess.offsets.sport_fl6);
        new_guess.values.sport_fl6 = bpf_ntohs(new_guess.values.sport_fl6);
        break;
    case GUESS_DPORT_FL6:
        new_guess.offsets.dport_fl6 = aligned_offset(subject, guess->offsets.dport_fl6, SIZEOF_DPORT_FL6);
        bpf_probe_read_kernel(&new_guess.values.dport_fl6, sizeof(new_guess.values.dport_fl6), subject + new_guess.offsets.dport_fl6);
        new_guess.values.dport_fl6 = bpf_ntohs(new_guess.values.dport_fl6);
        break;
    case GUESS_NETNS:
        new_guess.offsets.netns = aligned_offset(subject, guess->offsets.netns, SIZEOF_NETNS);
        bpf_probe_read_kernel(&possible_skc_net, sizeof(possible_net_t*), subject + new_guess.offsets.netns);
        if (!possible_skc_net) {
            new_guess.status.err = 1;
            break;
        }
        // if we get a kernel fault, it means possible_skc_net
        // is an invalid pointer, signal an error so we can go
        // to the next offsets.netns
        new_guess.offsets.ino = aligned_offset(subject, guess->offsets.ino, SIZEOF_NETNS_INO);
        ret = bpf_probe_read_kernel(&possible_netns, sizeof(possible_netns), (char*)possible_skc_net + new_guess.offsets.ino);
        if (ret == -EFAULT) {
            new_guess.status.err = 1;
            break;
        }
        //log_debug("netns: off=%u ino=%u val=%u\n", guess->offsets.netns, guess->offsets.ino, possible_netns);
        new_guess.values.netns = possible_netns;
        break;
    case GUESS_RTT:
        new_guess.offsets.rtt = aligned_offset(subject, guess->offsets.rtt, SIZEOF_RTT);
        bpf_probe_read_kernel(&new_guess.values.rtt, sizeof(new_guess.values.rtt), subject + new_guess.offsets.rtt);
        // We know that these two fields are always next to each other, 4 bytes apart:
        // https://elixir.bootlin.com/linux/v4.6/source/include/linux/tcp.h#L232
        // rtt -> srtt_us
        // rtt_var -> mdev_us
        new_guess.offsets.rtt_var = aligned_offset(subject, new_guess.offsets.rtt + SIZEOF_RTT, SIZEOF_RTT_VAR);
        bpf_probe_read_kernel(&new_guess.values.rtt_var, sizeof(new_guess.values.rtt_var), subject + new_guess.offsets.rtt_var);
        // For more information on the bit shift operations see:
        // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
        new_guess.values.rtt = new_guess.values.rtt >> 3;
        new_guess.values.rtt_var = new_guess.values.rtt_var >> 2;
        break;
    case GUESS_DADDR_IPV6:
        if (!check_family((struct sock*)subject, guess, AF_INET6)) {
            break;
        }

        new_guess.offsets.daddr_ipv6 = aligned_offset(subject, guess->offsets.daddr_ipv6, SIZEOF_DADDR_IPV6);
        bpf_probe_read_kernel(new_guess.values.daddr_ipv6, sizeof(u32) * 4, subject + new_guess.offsets.daddr_ipv6);
        break;
    case GUESS_SOCKET_SK:
        // Note that in this line we're essentially dereferencing a pointer
        // subject initially points to a (struct socket*), and we're trying to guess the offset of
        // (struct socket*)->sk which points to a (struct sock*) object.
        new_guess.offsets.socket_sk = aligned_offset(subject, guess->offsets.socket_sk, SIZEOF_SOCKET_SK);
        bpf_probe_read_kernel(&subject, sizeof(subject), subject + new_guess.offsets.socket_sk);
        bpf_probe_read_kernel(&new_guess.values.sport_via_sk, sizeof(new_guess.values.sport_via_sk), subject + new_guess.offsets.sport);
        bpf_probe_read_kernel(&new_guess.values.dport_via_sk, sizeof(new_guess.values.dport_via_sk), subject + new_guess.offsets.dport);
        new_guess.values.sport_via_sk = bpf_ntohs(new_guess.values.sport_via_sk);
        new_guess.values.dport_via_sk = bpf_ntohs(new_guess.values.dport_via_sk);
        break;
    case GUESS_SK_BUFF_SOCK:
        // Note that in this line we're essentially dereferencing a pointer
        // subject initially points to a (struct sk_buff*), and we're trying to guess the offset of
        // (struct sk_buff*)->sk which points to a (struct sock*) object.
        new_guess.offsets.sk_buff_sock = aligned_offset(subject, guess->offsets.sk_buff_sock, SIZEOF_SK_BUFF_SOCK);
        bpf_probe_read_kernel(&subject, sizeof(subject), subject + new_guess.offsets.sk_buff_sock);
        bpf_probe_read_kernel(&new_guess.values.sport_via_sk_via_sk_buff, sizeof(new_guess.values.sport_via_sk_via_sk_buff), subject + new_guess.offsets.sport);
        bpf_probe_read_kernel(&new_guess.values.dport_via_sk_via_sk_buff, sizeof(new_guess.values.dport_via_sk_via_sk_buff), subject + new_guess.offsets.dport);
        new_guess.values.sport_via_sk_via_sk_buff = bpf_ntohs(new_guess.values.sport_via_sk_via_sk_buff);
        new_guess.values.dport_via_sk_via_sk_buff = bpf_ntohs(new_guess.values.dport_via_sk_via_sk_buff);
        break;
    case GUESS_SK_BUFF_TRANSPORT_HEADER:
        new_guess.offsets.sk_buff_transport_header = aligned_offset(subject, guess->offsets.sk_buff_transport_header, SIZEOF_SK_BUFF_TRANSPORT_HEADER);
        bpf_probe_read_kernel(&new_guess.values.transport_header, sizeof(new_guess.values.transport_header), subject + new_guess.offsets.sk_buff_transport_header);
        bpf_probe_read_kernel(&new_guess.values.network_header, sizeof(new_guess.values.network_header), subject + new_guess.offsets.sk_buff_transport_header + sizeof(__u16));
        bpf_probe_read_kernel(&new_guess.values.mac_header, sizeof(new_guess.values.mac_header), subject + new_guess.offsets.sk_buff_transport_header + 2*sizeof(__u16));
        break;
    case GUESS_SK_BUFF_HEAD:
        // Loading the head field into `subject`.
        new_guess.offsets.sk_buff_head = aligned_offset(subject, guess->offsets.sk_buff_head, SIZEOF_SK_BUFF_HEAD);
        bpf_probe_read_kernel(&subject, sizeof(subject), subject + new_guess.offsets.sk_buff_head);
        // Loading source and dest ports.
        // The ports are located in the transport section (subject + guess->transport_header), if the traffic is udp or tcp
        // the source port is the first field in the struct (16 bits), and the dest is the second field (16 bits).
        bpf_probe_read_kernel(&new_guess.values.sport_via_sk_buff, sizeof(new_guess.values.sport_via_sk_buff), subject + guess->values.transport_header);
        bpf_probe_read_kernel(&new_guess.values.dport_via_sk_buff, sizeof(new_guess.values.dport_via_sk_buff), subject + guess->values.transport_header + sizeof(__u16));
        new_guess.values.sport_via_sk_buff = bpf_ntohs(new_guess.values.sport_via_sk_buff);
        new_guess.values.dport_via_sk_buff = bpf_ntohs(new_guess.values.dport_via_sk_buff);
        break;
    default:
        // not for us
        return 0;
    }

    bpf_map_update_elem(&tracer_guess, &zero, &new_guess, BPF_ANY);

    return 0;
}

static __always_inline bool is_sk_buff_event(__u64 what) {
    return what == GUESS_SK_BUFF_SOCK || what == GUESS_SK_BUFF_TRANSPORT_HEADER || what == GUESS_SK_BUFF_HEAD;
}

SEC("kprobe/ip_make_skb")
int kprobe__ip_make_skb(struct pt_regs* ctx) {
    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);

    if (guess == NULL || is_sk_buff_event(guess->status.what)) {
        return 0;
    }

    struct flowi4* fl4 = (struct flowi4*)PT_REGS_PARM2(ctx);
    guess_offsets(guess, (char*)fl4);
    return 0;
}

SEC("kprobe/ip6_make_skb")
int kprobe__ip6_make_skb(struct pt_regs* ctx) {
    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    if (guess == NULL || is_sk_buff_event(guess->status.what)) {
        return 0;
    }
    struct flowi6* fl6 = (struct flowi6*)PT_REGS_PARM7(ctx);
    guess_offsets(guess, (char*)fl6);
    return 0;
}

SEC("kprobe/ip6_make_skb")
int kprobe__ip6_make_skb__pre_4_7_0(struct pt_regs* ctx) {
    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    if (guess == NULL || is_sk_buff_event(guess->status.what)) {
        return 0;
    }
    struct flowi6* fl6 = (struct flowi6*)PT_REGS_PARM9(ctx);
    guess_offsets(guess, (char*)fl6);
    return 0;
}

/* Used exclusively for offset guessing */
SEC("kprobe/tcp_getsockopt")
int kprobe__tcp_getsockopt(struct pt_regs* ctx) {
    int level = (int)PT_REGS_PARM2(ctx);
    int optname = (int)PT_REGS_PARM3(ctx);
    if (level != SOL_TCP || optname != TCP_INFO) {
        return 0;
    }

    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    if (guess == NULL || guess->status.what == GUESS_SOCKET_SK || is_sk_buff_event(guess->status.what)) {
        return 0;
    }
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    guess_offsets(guess, (char*)sk);

    return 0;
}

/* Used for offset guessing the struct socket->sk field */
SEC("kprobe/sock_common_getsockopt")
int kprobe__sock_common_getsockopt(struct pt_regs* ctx) {
    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    if (guess == NULL || guess->status.what != GUESS_SOCKET_SK) {
        return 0;
    }

    struct socket* socket = (struct socket*)PT_REGS_PARM1(ctx);
    guess_offsets(guess, (char*)socket);
    return 0;
}

// Used for offset guessing (see: pkg/ebpf/offsetguess.go)
SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs* ctx) {
    struct sock* sk;
    u64 pid = bpf_get_current_pid_tgid();

    sk = (struct sock*)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY);

    return 0;
}

// Used for offset guessing (see: pkg/ebpf/offsetguess.go)
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs* __attribute__((unused)) ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 zero = 0;
    struct sock** skpp;
    tracer_guess_t* guess;
    skpp = bpf_map_lookup_elem(&connectsock_ipv6, &pid);
    if (skpp == 0) {
        return 0; // missed entry
    }

    struct sock* skp = *skpp;
    bpf_map_delete_elem(&connectsock_ipv6, &pid);

    guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    if (guess == NULL || is_sk_buff_event(guess->status.what)) {
        return 0;
    }
    // We should figure out offsets if they're not already figured out
    guess_offsets(guess, (char*)skp);

    return 0;
}

struct net_dev_queue_ctx {
    u64 unused;
    void* skb;
};

SEC("tracepoint/net/net_dev_queue")
int tracepoint__net__net_dev_queue(struct net_dev_queue_ctx* ctx) {
    u64 zero = 0;
    tracer_guess_t* guess = bpf_map_lookup_elem(&tracer_guess, &zero);
    // If we've triggered the hook and we are not under the context of guess offsets for GUESS_SK_BUFF_SOCK,
    // GUESS_SK_BUFF_TRANSPORT_HEADER, or GUESS_SK_BUFF_HEAD then we should do nothing in the hook.
    if (guess == NULL || !is_sk_buff_event(guess->status.what)) {
        return 0;
    }

    guess_offsets(guess, ctx->skb);
    return 0;
}

static __always_inline int guess_conntrack_offsets(conntrack_guess_t* guess, char* subject) {
    u64 zero = 0;

    if (guess->status.state != STATE_CHECKING) {
        return 1;
    }

    // Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
    // Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
    // with runtime.LockOSThread.
    proc_t proc = {};
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    if (!proc_t_comm_equals(guess->status.proc, proc)) {
        return 0;
    }

    conntrack_guess_t new_guess = {};
    // Copy values from status to new_guess
    bpf_probe_read_kernel(&new_guess, sizeof(conntrack_guess_t), guess);
    new_guess.status.state = STATE_CHECKED;
    bpf_probe_read_kernel(&new_guess.status.proc.comm, sizeof(proc.comm), proc.comm);

    possible_net_t* possible_ct_net = NULL;
    u32 possible_netns = 0;
    switch (guess->status.what) {
    case GUESS_CT_TUPLE_ORIGIN:
        new_guess.offsets.origin = aligned_offset(subject, guess->offsets.origin, SIZEOF_CT_TUPLE_ORIGIN);
        bpf_probe_read_kernel(&new_guess.values.saddr, sizeof(new_guess.values.saddr), subject + new_guess.offsets.origin);
        break;
    case GUESS_CT_TUPLE_REPLY:
        new_guess.offsets.reply = aligned_offset(subject, guess->offsets.reply, SIZEOF_CT_TUPLE_REPLY);
        bpf_probe_read_kernel(&new_guess.values.daddr, sizeof(new_guess.values.daddr), subject + new_guess.offsets.reply);
        break;
    case GUESS_CT_STATUS:
        new_guess.offsets.status = aligned_offset(subject, guess->offsets.status, SIZEOF_CT_STATUS);
        bpf_probe_read_kernel(&new_guess.values.status, sizeof(new_guess.values.status), subject + new_guess.offsets.status);
        break;
    case GUESS_CT_NET:
        new_guess.offsets.netns = aligned_offset(subject, guess->offsets.netns, SIZEOF_CT_NET);
        bpf_probe_read_kernel(&possible_ct_net, sizeof(possible_net_t*), subject + new_guess.offsets.netns);
        bpf_probe_read_kernel(&possible_netns, sizeof(possible_netns), ((char*)possible_ct_net) + guess->offsets.ino);
        new_guess.values.netns = possible_netns;
        break;
    default:
        // not for us
        return 0;
    }

    bpf_map_update_elem(&conntrack_guess, &zero, &new_guess, BPF_ANY);

    return 0;
}

static __always_inline bool is_ct_event(u64 what) {
    switch (what) {
    case GUESS_CT_TUPLE_ORIGIN:
    case GUESS_CT_TUPLE_REPLY:
    case GUESS_CT_STATUS:
    case GUESS_CT_NET:
        return true;
    default:
        return false;
    }
}

SEC("kprobe/__nf_conntrack_hash_insert")
int kprobe___nf_conntrack_hash_insert(struct pt_regs* ctx) {
    u64 zero = 0;
    conntrack_guess_t* guess = bpf_map_lookup_elem(&conntrack_guess, &zero);
    if (guess == NULL || !is_ct_event(guess->status.what)) {
        return 0;
    }

    void *ct = (void*)PT_REGS_PARM1(ctx);
    guess_conntrack_offsets(guess, (char*)ct);
    return 0;
}


char _license[] SEC("license") = "GPL";
