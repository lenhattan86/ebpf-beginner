#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Hello World! PID: %d\n", bpf_get_current_pid_tgid() >> 32);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
