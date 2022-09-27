#ifndef __COMMON_H__
#define __COMMON_H__

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define AF_INET			2
#define AF_INET6		10

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2

#define ENOENT       2
#define	E2BIG		 7
#define	EEXIST		17

#define TCP_FLAGS_OFFSET 13
#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

#endif
