#ifndef TELEMETRY_TYPES_H
#define TELEMETRY_TYPES_H

//#include <uapi/asm-generic/errno-base.h>

// We use a power of 2 array size so the upper bound of a map
// access can be easily constrained with an 'and' operation
#define T_MAX_ERRNO 64

typedef enum system_probe_maps {
    bpf_map_new_fd_args_telemetry_id=0,
    peo_args__telemetry_id,
    mmap_args_telemetry_id,
    fcntl_args_telemetry_id,

    oom_stats_telemetry_id,

    who_recvmsg_telemetry_id,
    who_sendmsg_telemetry_id,

    sockfd_lookup_args_telemetry_id,
    sock_by_pid_fd_telemetry_id,
    pid_fd_by_sock_telemetry_id,

    conntrack_telemetry_id,

    connectsock_ipv6_telemetry_id,
    tracer_status_telemetry_id,
    conntrack_status_telemetry_id,

    connection_states_telemetry_id,

    mongo_request_id_telemetry_id,

    connection_protocol_telemetry_id,

    http_in_flight_telemetry_id,
    offsets_data_telemetry_id,
    conn_tup_by_go_tls_conn_telemetry_id,

    http2_static_table_telemetry_id,

    kafka_last_tcp_seq_per_connection_telemetry_id,

    java_tls_connections_telemetry_id,
    java_conn_tuple_by_peer_telemetry_id,

    offsets_telemetry_id,

    conn_stats_telemetry_id,
    tcp_stats_telemetry_id,
    tcp_retransmits_telemetry_id,
    tcp_connect_args_telemetry_id,
    tcp_ongoing_connect_pid_telemetry_id,
    conn_close_batch_telemetry_id,
    tcp_sendmsg_args_telemetry_id,
    tcp_sendpage_args_telemetry_id,
    udp_sendmsg_args_telemetry_id,
    udp_sendpage_args_telemetry_id,
    tcp_recvmsg_args_telemetry_id,
    udp_recv_sock_telemetry_id,
    udpv6_recv_sock_telemetry_id,
    port_bindings_telemetry_id,
    udp_port_bindings_telemetry_id,
    pending_bind_telemetry_id,
    pending_tcp_retransmit_skb_telemetry_id,
    ip_make_skb_args_telemetry_id,
    conn_tuple_to_socket_skb_conn_tuple_telemetry_id,
    tcp_close_args_telemetry_id,

    perf_buffers_telemetry_id,
    ring_buffers_telemetry_id,
    perf_buffer_fds_telemetry_id,
    ring_buffer_fds_telemetry_id,
    map_pids_telemetry_id,
    perf_event_mmap_telemetry_id,

    ssl_sock_by_ctx_telemetry_id,
    ssl_read_args_telemetry_id,
    ssl_read_ex_args_telemetry_id,
    ssl_write_args_telemetry_id,
    ssl_write_ex_args_telemetry_id,
    bio_new_socket_args_telemetry_id,
    fd_by_ssl_bio_telemetry_id,
    ssl_ctx_by_pid_tgid_telemetry_id,
    go_tls_read_args_telemetry_id,
    go_tls_write_args_telemetry_id,

    http2_dynamic_table_telemetry_id,
    http2_dynamic_counter_table_telemetry_id,
    http2_in_flight_telemetry_id,
    http2_iterations_telemetry_id,

    open_at_args_telemetry_id,

    MAPS_MAX_ELEMENT,
} system_probe_maps_t;

typedef enum system_probe_probes {
    DATADOG_AGENT_RTLOADER_GIL_LOCKED = 0,
    DATADOG_AGENT_RTLOADER_GIL_UNLOCKED,
    PROBES_MAX_ELEMENT,
} system_probe_probes_t;

typedef struct {
    unsigned long err_count[T_MAX_ERRNO];
} errors_telemetry_t;

typedef enum helper_methods{
    read_indx=0,
    read_user_indx,
    read_kernel_indx,
    skb_load_bytes,
    perf_event_output,
    MAX_TELEMETRY_INDEX,
} helper_methods_t;
#define read_indx 0

#endif
