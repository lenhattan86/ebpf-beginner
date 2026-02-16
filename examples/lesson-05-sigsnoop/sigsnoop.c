#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct signal_data {
	u64 ts;
	u32 src_pid;
	u32 dst_pid;
	int sig;
	char src_comm[16];
	char dst_comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/signal/signal_generate")
int trace_signal(struct trace_event_raw_signal_generate *ctx) {
	struct signal_data *data;

	data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
	if (!data)
		return 0;

	data->ts = bpf_ktime_get_ns();
	data->src_pid = ctx->pid >> 32;
	data->dst_pid = ctx->sig;
	data->sig = ctx->errno;

	bpf_get_current_comm(&data->src_comm, sizeof(data->src_comm));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
