# Lesson 11: Bootstrap - Complete libbpf Project

## Overview

This lesson demonstrates a complete eBPF project using libbpf with user-space program development patterns. It traces both `exec()` and `exit()` system calls.

## Concepts Covered

- Full libbpf-based project structure
- Auto-generated vmlinux.h with vmlinux BTFs
- Multiple BPF programs in one object
- Efficient user-space harness
- Best practices for production eBPF code

## Implementation

This is a more advanced example requiring:

1. **vmlinux.h generation**: 
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```

2. **Build system**: Makefiles or CMake with proper dependencies

3. **User-space program**: Full error handling, signal management, structured logging

## Learning Objectives

- Understand complete eBPF program lifecycle
- Learn proper error handling in user-space code
- Apply best practices for production systems

## Further Reading

- [libbpf Documentation](https://github.com/libbpf/libbpf)
- [Linux Kernel BPF Documentation](https://docs.kernel.org/bpf/)
