#include "../vmlinux/vmlinux.h"

#include <ctype.h>
#include <string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
 */
struct sys_openat_enter_ctx {
    unsigned long long pr_regs_ptr;
    int __syscall_nr;
    unsigned int padding;
    int dfd;
    char* filename;
    unsigned int flags;
    umode_t mode;
};

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
 */
struct sys_openat_exit_ctx {
    unsigned long long pt_regs_ptr; //Pointer to pt_regs
    int __syscall_nr;
    long ret;
};

SEC("tp/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct sys_openat_enter_ctx *ctx){
    pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

    char filename[256] = {0};
    bpf_probe_read_user(&filename, 256, (char*)ctx->filename);

    bpf_printk("TP ENTRY pid = %d, filename = %s\n", pid, filename);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct sys_openat_exit_ctx *ctx){
    pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

    int ret_val = ctx->ret;
	bpf_printk("TP EXIT: pid = %d, ret = %ld\n", pid, ret_val);

    return 0;
}