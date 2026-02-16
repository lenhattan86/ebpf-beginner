#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	u32 pid;
	char comm[16];
	char filename[256];
	int flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	// Read filename and flags from syscall args
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
				(void *)ctx->args[1]);
	bpf_probe_read_kernel(&e->flags, sizeof(e->flags),
			      (void *)&ctx->args[2]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
