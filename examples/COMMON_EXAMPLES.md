# Common eBPF Examples & Patterns for Beginners

This document catalogs common eBPF use cases and patterns found in the broader ecosystem. These are reference examples that are useful as learning material.

## 1. Hello World – Basic BPF Program

**What:** Minimal eBPF program that does nothing but verifies the toolchain works.
**Pattern:** Load a BPF program, attach it to a kprobe/tracepoint, log to kernel ring buffer.
**Key Concepts:**
- BPF program loading and verification
- Ring buffer output
- Kernel log reading (`dmesg`, `journalctl`)
**Tools:** bpftrace, libbpf, ebpf-go
**Real-world use:** Debugging BPF programs, verifying toolchain setup

---

## 2. Syscall Tracing

**What:** Monitor system calls (open, read, write, connect, etc.) in real time.
**Pattern:** Attach to `sys_enter_*` or `sys_exit_*` tracepoints.
**Key Concepts:**
- Tracepoint anatomy
- Capturing syscall arguments
- Filtering by PID, UID, return code
**Example Keywords:** `strace` replacement, syscall filtering
**Real-world use:** Performance debugging, security auditing, anomaly detection

---

## 3. Process Execution & Fork Tracing

**What:** Track when processes are created (`fork`, `execve`) and terminated (`exit`).
**Pattern:** Attach to tracepoints: `sched_process_fork`, `sched_process_exec`, `sched_process_exit`.
**Key Concepts:**
- Parent-child PID relationships
- Command name capture
- Exit code tracking
**Example Keywords:** Process genealogy, process birth/death events
**Real-world use:** Container/pod lifecycle monitoring, security event logging

---

## 4. File I/O Tracing

**What:** Monitor file operations: open, read, write, fsync, unlink.
**Pattern:** Attach to `sys_enter_open*`, `sys_enter_write`, `sys_enter_read`, etc.
**Key Concepts:**
- Filename extraction from syscall args
- I/O size aggregation
- Per-process I/O accounting
**Example Keywords:** I/O profiling, disk tracing
**Real-world use:** Identify hot files, I/O bottlenecks in applications

---

## 5. Network Tracing

### a) Syscall-based (TCP connect, listen, sendto)
**What:** Monitor `connect()`, `listen()`, `sendto()`, `recvfrom()` syscalls.
**Pattern:** Attach to `sys_enter_connect`, etc.
**Key Concepts:** IP + port extraction, connection state tracking
**Real-world use:** Service discovery, connection anomaly detection

### b) XDP (eXpress Data Path)
**What:** Inspect/drop/redirect packets at network driver level.
**Pattern:** Attach BPF program to NIC hardware (or kernel driver).
**Key Concepts:**
- Packet header parsing
- Early termination (XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT)
- Direct hardware offload
**Real-world use:** DDoS mitigation, load balancing, packet filtering

### c) TC (Traffic Control)
**What:** Monitor or manipulate traffic control queueing.
**Pattern:** Attach BPF to Linux TC ingress/egress hooks.
**Key Concepts:** Per-flow rate limiting, packet marking, traffic shaping
**Real-world use:** Network policy enforcement, QoS

---

## 6. Memory & Heap Analysis

**What:** Track memory allocations (malloc, mmap) and detect leaks.
**Pattern:** Attach to `sys_enter_mmap`, `sys_enter_brk`, or instrument libc via USDT probes.
**Key Concepts:**
- Stack unwinding (stack traces)
- Allocation attribution by caller
- Memory aggregation by function/file
**Example Keywords:** Memory profiler, leak detector
**Real-world use:** Application profiling, memory leak detection

---

## 7. CPU Scheduling & Latency

**What:** Measure how long tasks wait in the run queue (run queue latency).
**Pattern:** Attach to `sched_wakeup` and `sched_switch` tracepoints, measure time delta.
**Key Concepts:**
- Event correlation (pair wake-up with dispatch)
- Histogram building
- Per-task/per-CPU aggregation
**Example Keywords:** runqlat, scheduler latency profiling
**Real-world use:** Identify CPU contention, analyze scheduler behavior

---

## 8. Lock Contention & Mutex Analysis

**What:** Detect and measure lock contention in kernel or user-space code.
**Pattern:** Attach to mutex operations or use UWAIT (userspace lock wait) probes.
**Key Concepts:**
- Lock acquisition/release tracking
- Contention histogram
- Caller attribution
**Real-world use:** Multi-threaded application profiling

---

## 9. Container & Cgroup Filtering

**What:** Correlate kernel events with container/pod identity.
**Pattern:** Intercept events, extract cgroup ID, map to container via cgroup paths or API.
**Key Concepts:**
- cgroup v1 vs. v2 path handling
- Container runtime APIs (containerd, docker)
- Cgroup ID ↔ container ID mapping
**Example Keywords:** Container-aware profiling, pod-scoped metrics
**Real-world use:** Kubernetes monitoring, multi-tenant isolation verification

---

## 10. Flame Graph Generation

**What:** Collect stack traces and generate flame graphs for visualization.
**Pattern:** Attach to sampling interrupt or specific events, capture call stacks.
**Key Concepts:**
- Stack unwinding (kernel + user space)
- Frame buffer for hundreds of stack samples
- Integration with flamegraph.pl or similar tools
**Example Keywords:** Performance profiling, hotspot analysis
**Real-world use:** Identify CPU hot spots, understand application flow

---

## 11. Performance Counters & PMU Access

**What:** Access hardware Performance Monitoring Unit (PMU) counters.
**Pattern:** Use BPF for hardware counter sampling.
**Key Concepts:**
- PMU event selection (cycles, cache misses, branch mispredicts)
- Per-CPU sampling
- High-frequency sampling without BPF overhead
**Real-world use:** Detailed CPU performance analysis, low-latency profiling

---

## 12. Kernel Module & Driver Hooking

**What:** Instrument kernel driver functions or module entry points.
**Pattern:** Use kprobes or kretprobes on specific kernel functions.
**Key Concepts:**
- Function argument/return value extraction
- Dynamic probing (no recompile)
**Example Keywords:** Device driver profiling, subsystem instrumentation
**Real-world use:** Hardware debugging, driver performance analysis

---

## 13. LSM (Linux Security Module) Programs

**What:** Implement custom security policies at the kernel level.
**Pattern:** Attach to LSM hooks: `bprm_check_security`, `file_open`, `task_kill`, etc.
**Key Concepts:**
- Deny/allow decision making
- Security context access (uid, gid, capabilities)
- Audit-friendly logging
**Requires:** Linux 5.8+
**Real-world use:** Fine-grained access control, compliance enforcement

---

## 14. USDT (User Statically Defined Tracepoints)

**What:** Hook application-defined tracepoints in user-space code (PostgreSQL, MySQL, Node.js, Python).
**Pattern:** Attach BPF to USDT markers in libraries/applications.
**Key Concepts:**
- Semaphore-based enable/disable
- Low overhead when disabled
- Application-specific context
**Real-world use:** Application-level observability without code changes

---

## 15. Socket Filtering (SO_ATTACH_BPF)

**What:** Attach BPF to individual sockets for filtering.
**Pattern:** Classic BPF (not eBPF) attached to socket via SO_ATTACH_BPF.
**Key Concepts:**
- Per-socket filtering rules
- Legacy BPF vs. eBPF differences
**Real-world use:** Custom network filtering per connection

---

## 16. Ring Buffer vs. Perf Buffer

**What:** Compare two methods for kernel-to-userspace event delivery.
**Ring Buffer (5.8+):**
- Single shared buffer
- Lower CPU overhead
- Better for high-volume events
**Perf Buffer (older):**
- Per-CPU buffer
- Historically more stable
- Can be wasteful on high-core systems
**Real-world use:** Choose based on event volume and kernel version

---

## 17. BPF Maps for Aggregation

**What:** Use in-kernel maps to aggregate, filter, and correlate data.
**Map Types:**
- `BPF_MAP_TYPE_HASH_MAP` — key-value storage
- `BPF_MAP_TYPE_ARRAY` — fixed-size array (fast lookups)
- `BPF_MAP_TYPE_PERCPU_HASH_MAP` — per-CPU hash (no lock contention)
- `BPF_MAP_TYPE_HISTOGRAM` — histogram buckets
**Real-world use:** State machine tracking, event deduplication, per-flow accounting

---

## 18. BPF Tail Calls

**What:** Call one BPF program from another (up to 32 chained calls).
**Pattern:** Use `bpf_tail_call()` to dispatch to different handlers.
**Key Concepts:**
- Program chaining without return
- State passing via BPF context
- Limits: 32 nested calls max
**Real-world use:** Complex protocol parsing, dynamic dispatch

---

## 19. CO-RE (Compile Once, Run Everywhere)

**What:** Use BTF (BPF Type Format) to write portable BPF code across kernel versions.
**Pattern:** Define structs with BTF, libbpf automatically adjusts for kernel version.
**Key Concepts:**
- vmlinux.h (auto-generated kernel header)
- BTF-based relocations
- No manual offset calculations
**Requires:** Linux 5.8+, available BTF
**Real-world use:** Distribution-friendly BPF programs

---

## 20. Ringbuffer for In-Kernel Processing

**What:** Ring buffers for kernel-to-userspace streaming with minimal overhead.
**Pattern:** Use `BPF_MAP_TYPE_RINGBUF`, read from userspace.
**Key Concepts:**
- Single shared buffer (unlike perf per-CPU)
- Ordered event delivery
- Busy poll or epoll-based reading
**Requires:** Linux 5.8+
**Real-world use:** High-throughput event streaming, low-latency tracing

---

## Learning Path

1. **Beginner** → Hello World, Syscall Tracing (understand loading, basic output)
2. **Intermediate** → Process Tracing, File I/O, Container Filtering (add complexity, map usage)
3. **Advanced** → Scheduling latency, XDP, LSM, USDT (specialized domains)
4. **Expert** → Kernel instrumentation, driver hooking, performance counters (kernel internals)

---

## Ecosystem Tools & Resources

- **bpftrace** — high-level tracing language (quick one-liners)
- **libbpf** — canonical C library for BPF loading
- **cilium/ebpf** — Go library for eBPF
- **bcc (BPF Compiler Collection)** — Python+C framework
- **Brendan Gregg's BPF Tools** — repository of practical tools
- **Cilium** — production-grade eBPF networking

---

## Key Takeaways

1. **Patterns repeat:** Most eBPF programs follow a few canonical patterns (attach → collect → aggregate).
2. **Tooling matters:** Different languages/frameworks (C, Go, Python) offer different ergonomics.
3. **Kernel version dependency:** Check kernel features (5.8 for CO-RE, 5.10 for ringbuf, etc.).
4. **Start simple:** Begin with syscall/kprobe tracing before moving to specialized domains.
