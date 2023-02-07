#include "../vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_sys_openat2")
int sys_open_kprobe(struct pt_regs *ctx)
{
	pid_t pid;
	char filename[64];

	pid = bpf_get_current_pid_tgid() >> 32;
	
	int res = bpf_probe_read(&filename, sizeof(filename), (ctx->si)); //rsi = filename
	bpf_printk("Read: %d", res);

	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe/__x64_sys_openat2")
int sys_open_kretprobe(struct pt_regs *ctx)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;

	int ret_val = ctx->ax;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret_val);
	return 0;
}