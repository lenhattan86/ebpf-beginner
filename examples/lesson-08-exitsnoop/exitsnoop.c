#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    int exitcode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_template")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event *e;
    
    if (ctx->pid == 0)  // Skip kernel threads
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->pid = ctx->pid;
    e->ppid = ctx->ppid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __builtin_memcpy(&e->comm, ctx->comm, sizeof(e->comm));
    e->exitcode = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
