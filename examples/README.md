# eBPF Beginner — Examples (based on eunomia.dev tutorials)

This folder contains practical eBPF examples inspired by the [eunomia.dev tutorials](https://eunomia.dev/tutorials/). Each example teaches a specific eBPF pattern or technique.

## Structure

Each lesson folder contains:
- `*.c` — eBPF kernel program (C with CO-RE)
- `main.go` — Go userspace harness using cilium/ebpf
- README explaining the example

## Available Lessons

| Folder | Name | Topic | Description |
|--------|------|-------|-------------|
| `lesson-01-helloworld/` | Hello World | Basic Tracepoint | Hello World with ring buffer output, attach to sys_enter_openat |
| `lesson-02-kprobe/` | kprobe Monitoring | Kernel Probes | Monitor unlink() syscalls using kprobe, read kernel strings |
| `lesson-03-opensnoop/` | Opensnoop | Syscall Tracing | Capture open() syscalls with file paths and flags |
| `lesson-04-execsnoop/` | Execsnoop | Process Tracing | Monitor process execution (sched_process_exec) |
| `lesson-05-sigsnoop/` | Sigsnoop | Signal Tracing | Capture signal generation events |

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
