#include "kconfig.h"
#include "bpf_tracing.h"
#include "bpf_telemetry.h"
#include "bpf_builtins.h"

#include "offsets.h"

#include "protocols/classification/dispatcher-helpers.h"
#include "protocols/http/buffer.h"
#include "protocols/http/http.h"
#include "protocols/http2/decoding.h"
#include "protocols/kafka/kafka-parsing.h"
#include "protocols/tls/java/erpc_dispatcher.h"
#include "protocols/tls/java/erpc_handlers.h"
#include "protocols/tls/https.h"
#include "protocols/tls/native-tls.h"
#include "protocols/tls/tags-types.h"

SEC("socket/protocol_dispatcher")
int socket__protocol_dispatcher(struct __sk_buff *skb) {
    protocol_dispatcher_entrypoint(skb);
    return 0;
}

// This entry point is needed to bypass a memory limit on socket filters
// See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Known-issues
SEC("socket/protocol_dispatcher_kafka")
int socket__protocol_dispatcher_kafka(struct __sk_buff *skb) {
    dispatch_kafka(skb);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe__tcp_sendmsg, struct sock *sk) {
    log_debug("kprobe/tcp_sendmsg: sk=%llx\n", sk);
    // map connection tuple during SSL_do_handshake(ctx)
    map_ssl_ctx_to_sock(sk);

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb(struct pt_regs* ctx) {
    log_debug("tracepoint/net/netif_receive_skb\n");
    // flush batch to userspace
    // because perf events can't be sent from socket filter programs
    http_batch_flush(ctx);
    http2_batch_flush(ctx);
    kafka_batch_flush(ctx);
    return 0;
}

// GO TLS PROBES placeholders

// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Write")
int uprobe__crypto_tls_Conn_Write(struct pt_regs *ctx) {
    return 0;
}

// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Write/return")
int uprobe__crypto_tls_Conn_Write__return(struct pt_regs *ctx) {
    return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read")
int uprobe__crypto_tls_Conn_Read(struct pt_regs *ctx) {
    return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read/return")
int uprobe__crypto_tls_Conn_Read__return(struct pt_regs *ctx) {
    return 0;
}

// func (c *Conn) Close(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Close")
int uprobe__crypto_tls_Conn_Close(struct pt_regs *ctx) {
    return 0;
}


char _license[] SEC("license") = "GPL";
