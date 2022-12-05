#ifndef _VULNPROBE_H_
#define _VULNPROBE_H_

#include "defs.h"
#include "process.h"

struct vulnprobe_event_t {
    struct kevent_t event;
    struct process_context_t process;
    struct span_context_t span;
    struct container_context_t container;

    u64 id;
};

#define MAX_CHECK_LEN 9 // max value to avoid "error: loop not unrolled: the optimizer was unable to perform the requested transformation"

struct vulnarg {
    u8 tocheck;
    u8 toderef;
    u8 len;
    u8 offset;
    u8 val[MAX_CHECK_LEN];
};

struct vulnargs {
    struct vulnarg arg1;
    struct vulnarg arg2;
    struct vulnarg arg3;
    struct vulnarg arg4;
    struct vulnarg arg5;
};

struct bpf_map_def SEC("maps/vulnargs") vulnargs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct vulnargs),
    .max_entries = 32,
};

__attribute__((always_inline)) static struct vulnargs* vulnargs_lookup(u64 id) {
    u64 key = id;
    struct vulnargs* args = bpf_map_lookup_elem(&vulnargs, &key);
    return args;
}

__attribute__((always_inline)) static u64 load_vuln_id() {
    u64 vuln_id = 0;
    LOAD_CONSTANT("vuln_id", vuln_id);
    return vuln_id;
}

__attribute__((always_inline)) static u64 load_vuln_rule_id() {
    u64 vuln_id = 0;
    LOAD_CONSTANT("rule_vuln_id", vuln_id);
    return vuln_id;
}

__attribute__((always_inline)) static u8 check_vulnarg(u64 val, struct vulnarg *arg) {
    if (arg->toderef == 0) {
        u16 tocheck16;
        u32 tocheck32;
        u64 tocheck64;

        switch (arg->len) {
        case 1:
            bpf_printk("val: %x, tocheck: %x\n", val, (u8)*arg->val);
            return (arg->val[0] == (u8)val);
        case 2:
            bpf_probe_read(&tocheck16, sizeof(tocheck16), arg->val);
            bpf_printk("val: %x, tocheck16: %x\n", (u16)val, tocheck16);
            return (tocheck16 == (u16)val);
        case 4:
            bpf_probe_read(&tocheck32, sizeof(tocheck32), arg->val);
            bpf_printk("val: %x, tocheck32: %x\n", (u32)val, tocheck32);
            return (tocheck32 == (u32)val);
        case 8:
            bpf_probe_read(&tocheck64, sizeof(tocheck64), arg->val);
            bpf_printk("val: %lx, tocheck64: %lx\n", val, tocheck64);
            return (tocheck64 == (u64)val);
        }
    } else { /* toderef */
        u8 argstr[MAX_CHECK_LEN];
        long len = bpf_probe_read_str(&argstr, MAX_CHECK_LEN, (void*)val);
        bpf_printk("val: (%s) len %li\n", argstr, len);
        if (len != arg->len) {
            return 0;
        }

        u8 tocheckstr[MAX_CHECK_LEN];
        long len2 = bpf_probe_read_str(&tocheckstr, MAX_CHECK_LEN, (void*)arg->val);
        bpf_printk("val2: (%s) len %li\n", tocheckstr, len2);

#pragma unroll
        for (int i = 0; i < MAX_CHECK_LEN && i < len; i++) {
            if (argstr[i] != tocheckstr[i]) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

SEC("uprobe/vuln_detector")
int uprobe_vuln_detector(struct pt_regs *ctx)
{
    u64 id = load_vuln_id();
    u64 rule_id = load_vuln_rule_id();
    bpf_printk("vulnprobe id %lu / rule_id %lu\n", id, rule_id);

    struct vulnargs* args = vulnargs_lookup(rule_id);
    if (args) {
        if ((args->arg1.tocheck == 0 || check_vulnarg(PT_REGS_PARM1(ctx), &(args->arg1)))
            && (args->arg2.tocheck == 0 || check_vulnarg(PT_REGS_PARM2(ctx), &(args->arg2)))
            && (args->arg3.tocheck == 0 || check_vulnarg(PT_REGS_PARM3(ctx), &(args->arg3)))
            && (args->arg4.tocheck == 0 || check_vulnarg(PT_REGS_PARM4(ctx), &(args->arg4)))
            && (args->arg5.tocheck == 0 || check_vulnarg(PT_REGS_PARM5(ctx), &(args->arg5)))) {
            bpf_printk("args validated!\n", id);
        } else {
            bpf_printk("args NOT validated\n", id);
            return 0;
        }
    } else {
        bpf_printk("no vulnargs provided, send the event anyway\n", id);
    }

    /* constuct and send the event */
    struct vulnprobe_event_t event = {
        .id = id,
    };
    struct proc_cache_t *entry = fill_process_context(&event.process);
    fill_container_context(entry, &event.container);
    fill_span_context(&event.span);
    send_event(ctx, EVENT_UPROBE, event);
    return 0;
}

#endif /* _VULNPROBE_H_ */
