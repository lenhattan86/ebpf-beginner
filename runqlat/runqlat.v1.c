//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __inline __u64 bpf_log2l(__u64 v) {
    __u64 r = 0;
    while (v >>= 1) {
        r++;
    }
    return r;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

typedef struct pid_key {
    u32 id;
    u32 slot;
} pid_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 204800);  
    __type(key, struct pid_key);
    __type(value, u32);       
} dist SEC(".maps");

static int trace_enqueue(struct task_struct *p) {
    if (!p) return 0; 

    __u32 tgid = 0, pid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid);
    bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid);

    if (0 || pid == 0)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int sched_wakeup(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *p = NULL;
    bpf_probe_read_kernel(&p, sizeof(p), (void *)&ctx->args[0]);

    return trace_enqueue(p);
}

SEC("raw_tracepoint/sched_wakeup_new")
int sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *p = NULL;
    bpf_probe_read_kernel(&p, sizeof(p), (void *)&ctx->args[0]);

    return trace_enqueue(p);
}

SEC("raw_tracepoint/sched_switch")
int sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid; 

    // ivcsw: treat like an enqueue event and store timestamp
    unsigned int prev_state = 0;
    bpf_probe_read_kernel(&prev_state, sizeof(prev_state), &prev->__state);
    if (prev_state == 0) { // TASK_RUNNING
        bpf_probe_read_kernel(&pid, sizeof(pid), &prev->pid);

        if (pid != 0) { //  non-idle
            u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
        }
    }

    bpf_probe_read_kernel(&tgid, sizeof(tgid), &next->tgid);
    bpf_probe_read_kernel(&pid, sizeof(pid), &next->pid);

    if (pid == 0) // idle
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; // us

    // store as histogram
    pid_key_t key = {}; 
    key.id = tgid; 
    key.slot = (u32)bpf_log2l(delta); 
    u32 *count;
    count = bpf_map_lookup_elem(&dist, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);  // Atomically increment
    } else {
        u64 init_count = 1;
        bpf_map_update_elem(&dist, &key, &init_count, BPF_ANY);
    }

    bpf_map_delete_elem(&start, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";