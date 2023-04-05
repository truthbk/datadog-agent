#ifndef _STRUCTS_SECURITY_PROFILE_H_
#define _STRUCTS_SECURITY_PROFILE_H_

#include "constants/custom.h"

struct security_profile_t {
    u64 cookie;
    u32 state;
};

struct security_profile_context_t {
    struct security_profile_t profile;
    u64 process_cookie;
    u32 callback;
    struct task_struct *process_tree[SECURITY_PROFILE_PROCESS_LOOKUP_MAX_DEPTH];
};

struct security_profile_syscalls_t {
    char syscalls[SYSCALL_ENCODING_TABLE_SIZE];
};

struct security_profile_process_cookie_t {
    u64 process_cookie;
    u64 profile_cookie;
};

#endif
