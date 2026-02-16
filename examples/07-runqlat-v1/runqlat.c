//go:build ignore
// #include <linux/sched.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


typedef __u32 u32; // Define u32 explicitly
typedef __u64 u64; // Define u64 explicitly

/*static __inline __u64 bpf_log2l(__u64 v) {
    __u64 r = 0;
    while (v >>= 1) {
        r++;
    }
    return r;
}*/


#define TASK_RUNNING 0


struct task_struct {
    __u32 pid;  // Process ID
    __u32 tgid; // Thread Group ID
    long __state;
};



// BPF_HASH(start, u32);
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// BPF_HISTOGRAM(dist, pid_key_t);

typedef struct pid_key {
    u32 id;
    u64 slot;
} pid_key_t;
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);  // Adjust based on histogram bucket size
    __type(key, struct pid_key);         // Histogram bucket (e.g., latency ranges)
    __type(value, u64);       // Count of occurrences in each bucket
} dist SEC(".maps");

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid){
    if (0 || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    // start.update(&pid, &ts);
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int sched_wakeup(struct bpf_raw_tracepoint_args *ctx) {
    // bpf_printk("sched_wakeup:");

    struct task_struct *p = NULL;

    // Read the task_struct pointer safely
    bpf_probe_read_kernel(&p, sizeof(p), (void *)&ctx->args[0]);
    if (!p) return 0;  // Ensure p is valid before use

    // Read `tgid` and `pid` safely
    __u32 tgid = 0, pid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid);
    bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid);

    // bpf_printk(" tgid=%d -> pid=%d\n", tgid, pid);
    

    return trace_enqueue(tgid, pid);
}

SEC("raw_tracepoint/sched_wakeup_new")
int sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *p = NULL;

    // Read the task_struct pointer safely
    bpf_probe_read_kernel(&p, sizeof(p), (void *)&ctx->args[0]);
    if (!p) return 0;  // Ensure p is valid before use

    // Read `tgid` and `pid` safely
    __u32 tgid = 0, pid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid);
    bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid);

    // bpf_printk(" tgid=%d -> pid=%d\n", tgid, pid);

    return trace_enqueue(tgid, pid);
}

/*
SEC("raw_tracepoint/sched_switch")
int sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->__state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(0 || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            // start.update(&pid, &ts);
            bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    if (0 || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    // tsp = start.lookup(&pid);
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;

    // store as histogram
    pid_key_t key = {}; 
    key.id = tgid; 
    key.slot = bpf_log2l(delta); 
    // dist.increment(key);
    u64 *count;
    count = bpf_map_lookup_elem(&dist, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);  // Atomically increment
    }

    // start.delete(&pid);
    bpf_map_delete_elem(&start, &pid);
    return 0;
}*/


SEC("raw_tracepoint/sched_switch")
int sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    // bpf_printk("Size of pid_key: %d", sizeof(struct pid_key));
    // bpf_printk("Offset of slot: %d", offsetof(struct pid_key, slot));

    // bpf_printk("sched_switch:");

    struct task_struct *prev = NULL, *next = NULL;

    // Read the task_struct pointers safely
    bpf_probe_read_kernel(&prev, sizeof(prev), (void *)&ctx->args[1]);
    bpf_probe_read_kernel(&next, sizeof(next), (void *)&ctx->args[2]);
    
    if (!prev || !next) return 0;  // Ensure they are valid before accessing

    u32 prev_tgid = 0, prev_pid = 0;
    u32 next_tgid = 0, next_pid = 0;
    
    // Read prev task_struct fields safely
    bpf_probe_read_kernel(&prev_tgid, sizeof(prev_tgid), &prev->tgid);
    bpf_probe_read_kernel(&prev_pid, sizeof(prev_pid), &prev->pid);
    
    // Read next task_struct fields safely
    bpf_probe_read_kernel(&next_tgid, sizeof(next_tgid), &next->tgid);
    bpf_probe_read_kernel(&next_pid, sizeof(next_pid), &next->pid);

    // Handle involuntary context switch
    if (prev_pid != 0) {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
    }

    if (next_pid == 0) return 0;

    // Fetch timestamp and calculate delta
    u64 *tsp = bpf_map_lookup_elem(&start, &next_pid);
    if (!tsp) return 0;  // Missed enqueue

    u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;  // Convert to microseconds

    // Store as histogram
    pid_key_t key = {}; 
    key.id = next_tgid; 
    key.slot = delta; 

    u64 *count = bpf_map_lookup_elem(&dist, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);  // Atomically increment
        // bpf_printk(" bpf_map_update_elem next_tgid=%d delta=%d count=%d \n", next_tgid, delta, *count);
    } else {
        u64 init_count = 1;
        bpf_map_update_elem(&dist, &key, &init_count, BPF_ANY);
        // bpf_printk(" bpf_map_update_elem init %d %d \n", next_tgid, delta);
    }

    bpf_map_delete_elem(&start, &next_pid);
    
    return 0;
}



char LICENSE[] SEC("license") = "GPL";