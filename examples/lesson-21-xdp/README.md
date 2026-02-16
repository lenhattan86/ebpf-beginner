# Lesson 21: eXpress Data Path (XDP)

## Overview

Learn XDP (eXpress Data Path) for high-performance packet processing at the network driver level, bypassing the kernel IP stack.

## Concepts Covered

- XDP program model
- Packet processing in driver context
- Return codes (PASS, DROP, TX, REDIRECT)
- Packet header manipulation
- DDoS mitigation strategies

## Key Techniques

- `BPF_PROG_TYPE_XDP` programs
- Direct packet buffer access
- Header parsing and modification
- Load balancing and forwarding
- Stateless packet filtering

## Learning Objectives

- Implement wire-speed packet processing
- Build custom load balancers
- Create DDoS protection mechanisms
- Understand performance-critical eBPF

## Performance Characteristics

- **Line-rate processing**: Gigabit+ throughput
- **Latency**: Sub-microsecond
- **Flexibility**: Programmable packet handling
- **Efficiency**: Minimal CPU usage

## Use Cases

- DDoS protection
- Load balancing
- Packet filtering
- In-network caching
- Service mesh data plane

## Resources

- [XDP Documentation](https://docs.kernel.org/networking/xdp.html)
- [IOVISOR project](https://www.iovisor.org/)
- [Cilium XDP Tutorial](https://docs.cilium.io/en/stable/bpf/)
