# Lesson 12: Performance Profiling with eBPF

## Overview

This lesson uses eBPF to create CPU flame graphs and performance profiles, sampling stack traces at a configurable frequency.

## Concepts Covered

- Stack trace sampling
- CPU profiling with eBPF
- Flame graph generation
- Performance analysis techniques

## Key Techniques

- `bpf_get_stackid()` for stack traces
- Per-CPU arrays for efficiency
- `perf_output()` for continuous data collection
- Integration with profiling tools

## Learning Objectives

- Learn stack trace collection with BPF
- Understand CPU-bound performance analysis
- Create actionable flame graphs

## Resources

- [Brendan Gregg's Flame Graphs](http://www.brendangregg.com/flamegraphs.html)
- [BPF Performance Tools](http://www.brendangregg.com/ebpf.html)
