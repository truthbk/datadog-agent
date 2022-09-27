#ifndef __FARGATE_TYPES_H
#define __FARGATE_TYPES_H

#ifndef __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

struct in6_addr {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
};

#endif

typedef enum
{
    CONN_DIRECTION_UNKNOWN = 0b00,
    CONN_DIRECTION_INCOMING = 0b01,
    CONN_DIRECTION_OUTGOING = 0b10,
} conn_direction_t;

typedef struct {
    u8 tcp_flags;
} skb_info_t;

typedef struct {
    struct in6_addr saddr;
    struct in6_addr daddr;
    u16 sport;
    u16 dport;
    u8  family;
    u8  protocol;
} tuple_t;

typedef struct {
    u64 sent_bytes;
    u64 recv_bytes;
    u64 timestamp;
    u32 flags;
    u32 cookie;
    u64 sent_packets;
    u64 recv_packets;
    u8 direction;
    u32 pid;
} conn_stats_t;

typedef struct {
    u32 retransmits;
    u32 rtt;
    u32 rtt_var;

    // Bit mask containing all TCP state transitions tracked by our tracer
    u16 state_transitions;
} tcp_stats_t;

typedef struct {
    tuple_t tup;
    conn_stats_t conn_stats;
    tcp_stats_t tcp_stats;
} conn_event_t;

#endif
