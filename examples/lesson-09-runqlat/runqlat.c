#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u64 ts;
    u32 pid;
    u32 cpu;
    u64 delta;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} start SEC(".maps");

SEC("tp/sched/sched_wakeup")
int trace_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
    u32 pid = ctx->pid;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, 0);
    return 0;
}

SEC("tp/sched/sched_switch")
int trace_switch(struct trace_event_raw_sched_switch *ctx)
{
    struct event *e;
    u32 pid = ctx->next_pid;
    u64 *tsp, delta;

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;

    delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &pid);

    if (delta < 1000000)  // Less than 1ms
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->pid = pid;
    e->cpu = bpf_get_smp_processor_id();
    e->delta = delta / 1000;  // Convert to us
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), (void *)ctx + ctx->__data_loc_next_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
