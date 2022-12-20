#ifndef _SOCKET_H_
#define _SOCKET_H_


__attribute__((always_inline)) u8 get_protocol_from_sock(struct sock *sk) {
    u64 sock_sk_protocol_offset;
    LOAD_CONSTANT("sock_sk_protocol_offset", sock_sk_protocol_offset);
    bpf_printk("constant sock_sk_protocol_offset: %lu\n", sock_sk_protocol_offset);

    u8 proto;
    bpf_probe_read(&proto, sizeof(proto), (void *)sk + sock_sk_protocol_offset);
    bpf_printk("proto: %u\n", proto);
    return (u8)proto;
}


#endif /* _SOCKET_H_ */
