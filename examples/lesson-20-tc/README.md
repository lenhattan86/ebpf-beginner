# Lesson 20: Traffic Control (TC)

## Overview

Use eBPF with Linux Traffic Control (TC) for advanced network packet manipulation, scheduling, and policy enforcement.

## Concepts Covered

- Traffic Control framework
- Qdisc (Queueing Discipline)
- Packet classification and marking
- Rate limiting and shaping
- Network packet manipulation

## Key Techniques

- `BPF_PROG_TYPE_SCHED_CLS` for classification
- `BPF_PROG_TYPE_SCHED_ACT` for actions
- Packet field manipulation
- Connection-aware policies

## Learning Objectives

- Implement custom QoS policies
- Shape and rate-limit traffic
- Build programmable network functions
- Monitor traffic patterns

## Use Cases

- DDoS mitigation
- Fair bandwidth sharing
- Prioritization policies
- Network isolation

## Resources

- [Linux TC Man Pages](http://lartc.org/)
- [BPF TC Examples](https://github.com/cilium/cilium/tree/main/bpf/tc/)
