//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16  // Define TASK_COMM_LEN manually

// Define an event structure to send data to user-space
struct event_t {
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

// Define a perf buffer map to send events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// eBPF program attached to tracepoint "sched_process_exec"
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
    struct event_t event = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.pid = pid;

    // Send event to user-space via perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Required license declaration
char __license[] SEC("license") = "Dual MIT/GPL";
