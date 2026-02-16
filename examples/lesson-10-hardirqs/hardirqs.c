#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u64 ts;
    u32 irq;
    u32 cpu;
    char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->irq = ctx->irq;
    e->cpu = bpf_get_smp_processor_id();
    bpf_probe_read_kernel_str(&e->name, sizeof(e->name), ctx->name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
