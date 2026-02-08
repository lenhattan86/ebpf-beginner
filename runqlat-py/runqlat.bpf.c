#if defined(BPF_LICENSE)
#error BPF_LICENSE cannot be specified through cflags
#endif
#if !defined(CONFIG_CC_STACKPROTECTOR)
#if defined(CONFIG_CC_STACKPROTECTOR_AUTO) \
    || defined(CONFIG_CC_STACKPROTECTOR_REGULAR) \
    || defined(CONFIG_CC_STACKPROTECTOR_STRONG)
#define CONFIG_CC_STACKPROTECTOR
#endif
#endif

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>

typedef struct pid_key {
    u32 id;
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u32 id;
    u64 slot;
} pidns_key_t;

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist, pid_key_t);

// record enqueue timestamp
__attribute__((always_inline))
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (0 || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &pid, &ts, BPF_ANY);
    return 0;
}

__attribute__((always_inline))
static __always_inline unsigned int pid_namespace(struct task_struct *task)
{

/* pids[] was removed from task_struct since commit 2c4704756cab7cfa031ada4dab361562f0e357c0
 * Using the macro INIT_PID_LINK as a conditional judgment.
 */
#ifdef INIT_PID_LINK
    struct pid_link pids;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;

    /*  get the pid namespace by following task_active_pid_ns(),
     *  pid->numbers[pid->level].ns
     */
    bpf_probe_read_kernel(&pids, sizeof(pids), &task->pids[PIDTYPE_PID]);
    bpf_probe_read_kernel(&level, sizeof(level), &pids.pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pids.pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);

    return ns.inum;
#else
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;

    /*  get the pid namespace by following task_active_pid_ns(),
     *  pid->numbers[pid->level].ns
     */
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->thread_pid);
    bpf_probe_read_kernel(&level, sizeof(level), &pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);

    return ns.inum;
#endif
}

__attribute__((section(".bpf.fn.raw_tracepoint__sched_wakeup")))
RAW_TRACEPOINT_PROBE(sched_wakeup)
{

    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&p->tgid); _val; }), ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&p->pid); _val; }));
}

__attribute__((section(".bpf.fn.raw_tracepoint__sched_wakeup_new")))
RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{

    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&p->tgid); _val; }), ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&p->pid); _val; }));
}

__attribute__((section(".bpf.fn.raw_tracepoint__sched_switch")))
RAW_TRACEPOINT_PROBE(sched_switch)
{

    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (({ typeof(unsigned int) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&prev->__state); _val; }) == TASK_RUNNING) {
        tgid = ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&prev->tgid); _val; });
        pid = ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&prev->pid); _val; });
        if (!(0 || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &pid, &ts, BPF_ANY);
        }
    }

    tgid = ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&next->tgid); _val; });
    pid = ({ typeof(pid_t) _val; __builtin_memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (void *)&next->pid); _val; });
    if (0 || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;

    // store as histogram
    pid_key_t key = {}; key.id = tgid; key.slot = bpf_log2l(delta); ({ typeof(dist.key) _key = key; typeof(dist.leaf) *_leaf = bpf_map_lookup_elem_(bpf_pseudo_fd(1, -2), &_key); if (_leaf) (*_leaf) += 1;else { typeof(dist.leaf) _zleaf; __builtin_memset(&_zleaf, 0, sizeof(_zleaf)); _zleaf += 1;bpf_map_update_elem_(bpf_pseudo_fd(1, -2), &_key, &_zleaf, BPF_NOEXIST); } });

    bpf_map_delete_elem((void *)bpf_pseudo_fd(1, -1), &pid);
    return 0;
}