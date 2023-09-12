#ifndef __OFFSET_GUESS_H
#define __OFFSET_GUESS_H

#include <linux/types.h>
#include <linux/sched.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

typedef struct {
    char comm[TASK_COMM_LEN];
} proc_t;

static const __u8 GUESS_SADDR = 0;
static const __u8 GUESS_DADDR = 1;
static const __u8 GUESS_FAMILY = 2;
static const __u8 GUESS_SPORT = 3;
static const __u8 GUESS_DPORT = 4;
static const __u8 GUESS_NETNS = 5;
static const __u8 GUESS_RTT = 6;
static const __u8 GUESS_DADDR_IPV6 = 7;
static const __u8 GUESS_SADDR_FL4 = 8;
static const __u8 GUESS_DADDR_FL4 = 9;
static const __u8 GUESS_SPORT_FL4 = 10;
static const __u8 GUESS_DPORT_FL4 = 11;
static const __u8 GUESS_SADDR_FL6 = 12;
static const __u8 GUESS_DADDR_FL6 = 13;
static const __u8 GUESS_SPORT_FL6 = 14;
static const __u8 GUESS_DPORT_FL6 = 15;
static const __u8 GUESS_SOCKET_SK = 16;
static const __u8 GUESS_SK_BUFF_SOCK = 17;
static const __u8 GUESS_SK_BUFF_TRANSPORT_HEADER = 18;
static const __u8 GUESS_SK_BUFF_HEAD = 19;
static const __u8 GUESS_CT_TUPLE_ORIGIN = 20;
static const __u8 GUESS_CT_TUPLE_REPLY = 21;
static const __u8 GUESS_CT_STATUS = 22;
static const __u8 GUESS_CT_NET = 23;

static const __u8 STATE_UNINITIALIZED = 0;
static const __u8 STATE_CHECKING = 1;
static const __u8 STATE_CHECKED = 2;
static const __u8 STATE_READY = 3;

typedef struct {
    __u64 saddr;
    __u64 daddr;
    __u64 sport;
    __u64 dport;
    __u64 netns;
    __u64 ino;
    __u64 family;
    __u64 rtt;
    __u64 rtt_var;

    __u64 daddr_ipv6;

    __u64 saddr_fl4;
    __u64 daddr_fl4;
    __u64 sport_fl4;
    __u64 dport_fl4;

    __u64 saddr_fl6;
    __u64 daddr_fl6;
    __u64 sport_fl6;
    __u64 dport_fl6;

    __u64 socket_sk;
    __u64 sk_buff_sock;
    __u64 sk_buff_transport_header;
    __u64 sk_buff_head;
} tracer_offsets_t;

typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
    __u16 family;
    __u32 rtt;
    __u32 rtt_var;

    __u32 daddr_ipv6[4];

    __u32 saddr_fl4;
    __u32 daddr_fl4;
    __u16 sport_fl4;
    __u16 dport_fl4;

    __u32 saddr_fl6[4];
    __u32 daddr_fl6[4];
    __u16 sport_fl6;
    __u16 dport_fl6;

    __u16 sport_via_sk;
    __u16 dport_via_sk;
    __u16 sport_via_sk_via_sk_buff;
    __u16 dport_via_sk_via_sk_buff;

    __u16 transport_header;
    __u16 network_header;
    __u16 mac_header;
} tracer_values_t;

typedef struct {
    __u64 state;
    __u64 what;
    __u64 err;

    proc_t proc;

    // tcp_info_kprobe_status records if the tcp_info kprobe has been triggered.
    // 0 - not triggered 1 - triggered
    __u64 tcp_info_kprobe_status;

    tracer_offsets_t offsets;
    tracer_values_t values;
} tracer_status_t;

typedef struct {
    __u64 origin;
    __u64 reply;
    __u64 status;
    __u64 netns;
    __u64 ino;
} conntrack_offsets_t;

typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u32 status;
    __u32 netns;
} conntrack_values_t;

typedef struct {
    __u64 state;
    __u64 what;
    __u64 err;

    /* checking */
    proc_t proc;

    conntrack_offsets_t offsets;
    conntrack_values_t values;
} conntrack_status_t;


#endif //__OFFSET_GUESS_H
