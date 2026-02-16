# Lesson 15: Capturing Java GC Durations Using USDT

## Overview

This advanced lesson demonstrates capturing User Statically Defined Tracepoints (USDT) to monitor Java Garbage Collection events.

## Concepts Covered

- USDTs (User Statically Defined Tracepoints)
- Java runtime instrumentation
- GC event correlation
- Dynamic tracing of managed runtimes

## Key Techniques

- `usdt` probes on Java runtime
- GC start/stop timestamp correlation
- JVM interaction with kernel tracing
- Multi-language instrumentation

## Learning Objectives

- Understand USDT-based tracing
- Monitor managed runtime performance
- Build observability for polyglot systems

## Prerequisites

- Java with JDWP or equivalent instrumentation
- Understanding of GC algorithms

## Resources

- [USDT Documentation](https://github.com/libbpf/libbpf/blob/master/docs/libbpf_build.md#usdt-probe)
- [Java Flight Recorder](https://docs.oracle.com/javacomponents/jmc-5-4/jfr-runtime-guide/)
