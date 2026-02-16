#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	u32 pid;
	char comm[16];
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int kprobe_unlinkat(struct pt_regs *ctx) {
	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
				  (void *)PT_REGS_PARM2(ctx));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
