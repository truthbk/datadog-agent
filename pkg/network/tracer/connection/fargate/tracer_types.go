// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ignore
// +build ignore

// +godefs map struct_in6_addr [16]byte /* in6_addr */

package fargate

/*
#include "../../../ebpf/c/co-re/fargate-types.h"
*/
import "C"

type Tuple C.tuple_t
type ConnStats C.conn_stats_t
type TCPStats C.tcp_stats_t
type ConnEvent C.conn_event_t

type ConnDirection uint8

const (
	Unknown  ConnDirection = C.CONN_DIRECTION_UNKNOWN
	Incoming ConnDirection = C.CONN_DIRECTION_INCOMING
	Outgoing ConnDirection = C.CONN_DIRECTION_OUTGOING
)
