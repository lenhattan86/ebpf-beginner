# eBPF Beginner — Examples (based on eunomia.dev tutorials)

This folder contains practical eBPF examples inspired by the [eunomia.dev tutorials](https://eunomia.dev/tutorials/). Each example teaches a specific eBPF pattern or technique.

## Structure

Each lesson folder contains:
- `*.c` — eBPF kernel program (C with CO-RE)
- `main.go` — Go userspace harness using cilium/ebpf
- README explaining the example

## Available Lessons

### Foundational (Lessons 0-10)

| Folder | Name | Topic | Description |
|--------|------|-------|-------------|
| `lesson-00-introduce/` | Introduction | Core Concepts | Essential eBPF concepts, tools, and architecture overview |
| `lesson-01-helloworld/` | Hello World | Basic Tracepoint | First eBPF program with ring buffer output |
| `lesson-02-kprobe/` | kprobe Monitoring | Kernel Probes | Monitor syscalls using dynamic kernel probes |
| `lesson-03-fentry-unlink/` | fentry Probes | Fast Function Probes | High-performance function entry probing (fentry) |
| `lesson-04-opensnoop/` | Opensnoop | Syscall Tracing | Capture file open operations with global variable filtering |
| `lesson-05-uprobe-bashreadline/` | Uprobe | User-Space Tracing | Monitor readline() library function calls |
| `lesson-06-sigsnoop/` | Sigsnoop | Signal Tracing | Capture signal generation and delivery events |
| `lesson-07-execsnoop/` | Execsnoop | Process Execution | Monitor process creation with execution details |
| `lesson-08-exitsnoop/` | Exitsnoop | Process Exit | Track process termination events |
| `lesson-09-runqlat/` | Runqlat | Scheduling Latency | Measure CPU scheduling latency with histograms |
| `lesson-10-hardirqs/` | Hardirqs | Interrupt Tracing | Monitor hardware interrupt handling |

### Advanced (Lessons 11-21)

| Folder | Name | Topic | Description |
|--------|------|-------|-------------|
| `lesson-11-bootstrap/` | Bootstrap | Production eBPF | Complete libbpf-based project structure |
| `lesson-12-profile/` | Profile | Performance Analysis | CPU profiling and flame graph generation |
| `lesson-13-tcpconnlat/` | TCP Latency | Network Monitoring | TCP connection setup latency analysis |
| `lesson-14-tcpstates/` | TCP States | Connection Tracking | TCP state transitions and RTT measurement |
| `lesson-15-javagc/` | Java GC | USDT Tracing | Capture Java garbage collection events |
| `lesson-16-memleak/` | Memory Leaks | Leak Detection | Identify memory leaks without stopping app |
| `lesson-17-biopattern/` | Disk I/O | Storage Analysis | Classify I/O patterns and latency |
| `lesson-18-further-reading/` | Resources | Reference | Curated learning materials and research papers |
| `lesson-19-lsm-connect/` | LSM Security | Access Control | Implement security policies using LSM hooks |
| `lesson-20-tc/` | Traffic Control | Network Shaping | Advanced packet manipulation and QoS |
| `lesson-21-xdp/` | XDP | Packet Processing | Wire-speed packet processing in driver context |

## Building & Running

### Prerequisites

Inside lima-k8s-ebpf VM:
- `clang` (for eBPF compilation)
- `libbpf` dev headers
- `linux-headers` matching kernel version
- `go` (for userspace harness)

### From Host (using helper script)

```bash
examples/run-example.sh lesson-02-kprobe
```

### Manual (inside VM)

```bash
limactl shell lima-k8s-ebpf

# Navigate to example
cd /Users/nhatle/projects/ebpf-beginner/examples/lesson-02-kprobe

# Compile eBPF program
clang -O2 -target bpf -c kprobe_unlink.c -o kprobe_unlink.o

# Build and run Go harness
go build -o /tmp/kprobe-demo .
sudo /tmp/kprobe-demo
```

## Example Output

### lesson-02-kprobe
```
PID	COMM		FILENAME
---	----		--------
1234	bash		/tmp/testfile
5678	rm		/home/user/file.txt
```

### lesson-03-opensnoop
```
PID	COMM			FILENAME
---	----			--------
1234	bash			/etc/passwd
5678	python3			/usr/lib/python3.9/...
```

### lesson-04-execsnoop
```
PID	PPID	COMM			FILENAME
---	----	----			--------
1234	1	bash			/usr/bin/ls
5678	1234	ls			/usr/bin/ls
```

## Key Concepts Covered

1. **Tracepoints** (lesson-01, 03, 04): Stable kernel hooks
2. **Kprobes** (lesson-02): Dynamic probes on kernel functions
3. **Ring Buffer** (all): Efficient kernel→userspace communication
4. **Kernel String Reading**: bpf_probe_read_kernel_str, bpf_probe_read_user_str
5. **Binary Event Parsing**: Decoding BPF event messages in userspace

## Resources

- **Eunomia.dev Tutorials:** https://eunomia.dev/tutorials/
- **Cilium eBPF Documentation:** https://docs.cilium.io/en/latest/bpf/
- **BPF and XDP Reference Guide:** https://docs.kernel.org/bpf/

## Next Steps

1. Study each lesson's C code to understand eBPF syntax
2. Modify the programs (e.g., filter by PID, change output format)
3. Combine lessons (e.g., execsnoop + opensnoop to trace process + files)
4. Explore advanced examples in `COMMON_EXAMPLES.md`
