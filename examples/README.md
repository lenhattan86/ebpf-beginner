eBPF Beginner — Go Examples

This folder describes the Go examples included in the repository and how to build/run them inside the `lima-k8s-ebpf` VM.

Prerequisites (inside the VM):
- `go` (installed by the VM provisioning)
- `clang`/`libbpf` (the VM provisioning installs these)

Common pattern (run from your macOS host):

```
# build & run example <name> inside the lima-k8s-ebpf VM
limactl shell lima-k8s-ebpf -- bash -lc "cd /Users/nhatle/projects/ebpf-beginner/<example> && go build -o /tmp/<example>-bin && sudo /tmp/<example>-bin"
```

Available Go examples (workspace paths):
- `cgroup2pod/` — map cgroup id to pod info (Go)
- `pidsofpods/` — list PIDs of pods (Go)
- `pidsofpodsfromcgroups/` — correlate cgroup -> pod PIDs (Go)
- `runqlat/` — runqlat instrumentation (Go harness)
- `runqlat.v1/` — older runqlat version (Go)
- `tracepoint/` — tracepoint example (Go)
- `vmlinux-demo/` — micro demo using vmlinux.h (Go)

Notes:
- The repository root is mounted into the VM via the lima config; the host path `/Users/nhatle/projects/ebpf-beginner` is available inside the VM at the same path.
- Some examples require root privileges to attach BPF programs or access perf events — the helper command above runs the binary with `sudo`.
- If an example has additional build instructions, check the example folder for `README` or `Makefile`.

Helper script
---------------
Use the included `run-example.sh` helper to build and run examples from the host.

Example:

```
/Users/nhatle/projects/ebpf-beginner/examples/run-example.sh runqlat
```

This will build the `runqlat` example inside the VM and run it with `sudo`.
