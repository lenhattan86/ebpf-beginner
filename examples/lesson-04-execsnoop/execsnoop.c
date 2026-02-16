#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	u32 pid;
	u32 ppid;
	char comm[16];
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = ctx->pid;
	e->ppid = ctx->ppid;
	__builtin_memcpy(&e->comm, ctx->comm, sizeof(e->comm));
	__builtin_memcpy(&e->filename, ctx->filename, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
