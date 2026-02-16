# Lesson 0: Introduction to Core Concepts and Tools

## Overview

This lesson provides an introduction to essential eBPF concepts and the tools needed for kernel monitoring and tracing.

## Key Concepts

- **eBPF (Extended Berkeley Packet Filter)**: A technology that allows safe, sandboxed kernel execution of custom programs
- **Kernel Space vs User Space**: Understanding the separation and communication between kernel and application code
- **Tracepoints**: Static kernel hooks for tracking specific events
- **Kprobes**: Dynamic probes on kernel functions
- **Uprobes**: Userspace probes on application functions
- **Ring Buffers**: Efficient bidirectional kernel↔user space communication
- **BPF Maps**: In-kernel data structures for sharing state

## Essential Tools

### eBPF Development
- `clang` — C compiler for eBPF programs
- `libbpf` — User-space library for loading/managing eBPF programs
- `vmlinux.h` — CO-RE (Compile Once Run Everywhere) kernel definitions
- `bpftool` — Inspection and management utility

### Userspace
- `cilium/ebpf` (Go library) — Load and manage eBPF programs from user space
- `perf` — Linux performance analysis tool
- `bpf()` syscall — Direct kernel interface for eBPF operations

## Architecture

```
Kernel Space         |  User Space
================================
[eBPF Program]       |  [Go Program]
[BPF Maps]      ←→   |  [Ring Buffer]
[Events]        ←→   |  [Data Display]
```

## Core eBPF Concepts

### 1. Attaching to Events
- **Tracepoints**: Static, always available hooks (stable ABI)
- **Kprobes**: Dynamic function entry/exit instrumentation
- **Fentry**: Function entry intercept (faster, fewer restrictions)
- **Uprobes**: User-space function tracing
- **Raw Tracepoints**: Direct kernel event access

### 2. Data Collection
- **Ring Buffers**: Ordered, low-overhead per-CPU buffers
- **Perf Event Arrays**: Asynchronous event collection
- **BPF Maps**: Hash tables, arrays, per-CPU storage for state

### 3. CO-RE (Compile Once, Run Everywhere)
- Uses vmlinux.h for kernel structure definitions
- Relocates field offsets at load time
- Supports different kernel versions without recompilation

## Learning Path

The following lessons build on these foundations:
1. **Hello World** — First eBPF program with ring buffer
2. **Kprobe** — Monitor system calls with kernel probes
3. **Fentry** — Faster function entry probes
4. **Opensnoop** — Capture file operations with filtering
5. **Uprobe** — Trace user-space library calls
6. **Sigsnoop** — Monitor signal delivery and handling
7. **Execsnoop** — Track process creation
8. **Exitsnoop** — Monitor process termination
9. **Runqlat** — Measure CPU scheduling latency
10. **Hardirqs** — Monitor kernel interrupt handling

## Tools Comparison

| Tool | Type | ABI | Overhead | Use Case |
|------|------|-----|----------|----------|
| Tracepoint | Static | Stable | Low | Stable, documented events |
| Kprobe | Dynamic | Unstable | Medium | Flexible, any function |
| Fentry | Dynamic | Stable | Very Low | Fast, modern kernels |
| Uprobe | Dynamic | N/A | Medium | Application tracing |
| Raw TP | Direct | Unstable | Very Low | Raw event access |

## Next Steps

1. Set up your development environment (clang, libbpf, Go)
2. Generate vmlinux.h for your kernel: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
3. Start with Lesson 1: Hello World
4. Build and run each example inside the lima-k8s-ebpf VM

## Resources

- [Cilium eBPF Docs](https://docs.cilium.io/en/latest/bpf/)
- [Linux eBPF Documentation](https://docs.kernel.org/bpf/)
- [Eunomia eBPF Collection](https://eunomia.dev/)
- [BPF Performance Tools](http://www.brendangregg.com/ebpf.html)
