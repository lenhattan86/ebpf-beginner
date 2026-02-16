#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Define a perf event map for sending data to user-space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
} events SEC(".maps");

struct switch_event {
    u32 prev_pid;
    u32 prev_tgid;
    u32 next_pid;
    u32 next_tgid;
};

SEC("raw_tracepoint/sched_switch")
int sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];

    struct switch_event event = {};
    bpf_probe_read_kernel(&event.prev_pid, sizeof(event.prev_pid), &prev->pid);
    bpf_probe_read_kernel(&event.prev_tgid, sizeof(event.prev_tgid), &prev->tgid);
    bpf_probe_read_kernel(&event.next_pid, sizeof(event.next_pid), &next->pid);
    bpf_probe_read_kernel(&event.next_tgid, sizeof(event.next_tgid), &next->tgid);

    // Send event to user-space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}
