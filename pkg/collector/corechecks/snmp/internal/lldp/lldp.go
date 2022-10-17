// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package lldp

// ChassisIDSubtypeMap TODO
var ChassisIDSubtypeMap = map[string]string{
	"1": "chassis_component",
	"2": "interface_alias",
	"3": "port_component",
	"4": "mac_address",
	"5": "network_address",
	"6": "interface_name",
	"7": "local",
}

// PortIDSubTypeMap TODO
var PortIDSubTypeMap = map[string]string{
	"1": "interface_alias",
	"2": "port_component",
	"3": "mac_address",
	"4": "network_address",
	"5": "interface_name",
	"6": "agent_circuit_id",
	"7": "local",
}

// RemManAddrSubtype TODO
//var RemManAddrSubtype = map[int]string{
//	0:     "other",
//	1:     "ipV4",
//	2:     "ipV6",
//	3:     "nsap",
//	4:     "hdlc",
//	5:     "bbn1822",
//	6:     "all802",
//	7:     "e163",
//	8:     "e164",
//	9:     "f69",
//	10:    "x121",
//	11:    "ipx",
//	12:    "appletalk",
//	13:    "decnetIV",
//	14:    "banyanVines",
//	15:    "e164withNsap",
//	16:    "dns",
//	17:    "distinguishedname",
//	18:    "asnumber",
//	19:    "xtpoveripv4",
//	20:    "xtpoveripv6",
//	21:    "xtpnativemodextp",
//	65535: "reserved",
//}
