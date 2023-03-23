#ifndef __KTYPES_H__
#define __KTYPES_H__

#ifdef COMPILE_CORE
#include "vmlinux.h"

// these must be defined before any other macros that might use them in arguments
// source include/net/flow.h
#define fl6_sport uli.ports.sport
#define fl6_dport uli.ports.dport
#define fl4_sport uli.ports.sport
#define fl4_dport uli.ports.dport


#else
#include <linux/types.h>
#include <linux/version.h>
#endif

#endif
