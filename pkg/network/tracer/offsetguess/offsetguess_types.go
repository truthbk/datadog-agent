// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ignore

package offsetguess

/*
#include "prebuilt/offset-guess.h"
*/
import "C"

type Proc C.proc_t

const ProcCommMaxLen = C.TASK_COMM_LEN - 1

type TracerOffsets C.tracer_offsets_t
type TracerValues C.tracer_values_t
type TracerStatus C.tracer_status_t

type State uint8

const (
	StateUninitialized State = C.STATE_UNINITIALIZED
	StateChecking      State = C.STATE_CHECKING // status set by userspace, waiting for eBPF
	StateChecked       State = C.STATE_CHECKED  // status set by eBPF, waiting for userspace
	StateReady         State = C.STATE_READY    // fully initialized, all offset known
)

type ConntrackOffsets C.conntrack_offsets_t
type ConntrackValues C.conntrack_values_t
type ConntrackStatus C.conntrack_status_t
type ConntrackState uint8

type GuessWhat uint64

const (
	GuessSAddr  GuessWhat = C.GUESS_SADDR
	GuessDAddr  GuessWhat = C.GUESS_DADDR
	GuessDPort  GuessWhat = C.GUESS_DPORT
	GuessFamily GuessWhat = C.GUESS_FAMILY
	GuessSPort  GuessWhat = C.GUESS_SPORT
	// Following values are associated with an UDP connection, used for guessing offsets
	// in the flowi4 data structure
	GuessSAddrFl4 GuessWhat = C.GUESS_SADDR_FL4
	GuessDAddrFl4 GuessWhat = C.GUESS_DADDR_FL4
	GuessSPortFl4 GuessWhat = C.GUESS_SPORT_FL4
	GuessDPortFl4 GuessWhat = C.GUESS_DPORT_FL4
	// Following values are associated with an UDPv6 connection, used for guessing offsets
	// in the flowi6 data structure
	GuessSAddrFl6 GuessWhat = C.GUESS_SADDR_FL6
	GuessDAddrFl6 GuessWhat = C.GUESS_DADDR_FL6
	GuessSPortFl6 GuessWhat = C.GUESS_SPORT_FL6
	GuessDPortFl6 GuessWhat = C.GUESS_DPORT_FL6

	GuessNetNS GuessWhat = C.GUESS_NETNS
	GuessRTT   GuessWhat = C.GUESS_RTT

	GuessSocketSK              GuessWhat = C.GUESS_SOCKET_SK
	GuessSKBuffSock            GuessWhat = C.GUESS_SK_BUFF_SOCK
	GuessSKBuffTransportHeader GuessWhat = C.GUESS_SK_BUFF_TRANSPORT_HEADER
	GuessSKBuffHead            GuessWhat = C.GUESS_SK_BUFF_HEAD

	GuessDAddrIPv6 GuessWhat = C.GUESS_DADDR_IPV6

	GuessCtTupleOrigin GuessWhat = C.GUESS_CT_TUPLE_ORIGIN
	GuessCtTupleReply  GuessWhat = C.GUESS_CT_TUPLE_REPLY
	GuessCtStatus      GuessWhat = C.GUESS_CT_STATUS
	GuessCtNet         GuessWhat = C.GUESS_CT_NET

	GuessNotApplicable GuessWhat = 99999
)
