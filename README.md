# ebpf-beginner

## Start up the k8s cluster:

```
$ limactl start --name=k8s k8s.yml
$ export KUBECONFIG="/Users/nhatle/.lima/k8s/copied-from-guest/kubeconfig.yaml
$ kubectl get nodes
NAME       STATUS   ROLES           AGE    VERSION
lima-k8s   Ready    control-plane   105m   v1.32.0
```

ssh to k8s node

```
$ limactl shell k8s
```

## Hello ebpf in python

ssh to k8s node

```
$ limactl shell k8s
```

```
$ cat hello-world.py
#!/usr/bin/python3
from bcc import BPF
program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello World!\\n");
return 0; }
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
b.trace_print()

$ sudo python3 hello-world.py
```


## Hello ebpf in go


gen.go
```
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c
```

```
$ go mod init ebpf-test
$ go mod tidy
$ go get github.com/cilium/ebpf/cmd/bpf2go
$ go generate
```

main.go

```
package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "time"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs counterObjects 
    if err := loadCounterObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    ifname := "eth0" // Change this to an interface on your machine.
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.CountPackets,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close() 

    log.Printf("Counting incoming packets on %s..", ifname)

    // Periodically fetch the packet counter from PktCount,
    // exit the program when interrupted.
    tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)
    for {
        select {
        case <-tick:
            var count uint64
            err := objs.PktCount.Lookup(uint32(0), &count) 
            if err != nil {
                log.Fatal("Map lookup:", err)
            }
            log.Printf("Received %d packets", count)
        case <-stop:
            log.Print("Received signal, exiting..")
            return
        }
    }
}
```

build and run

```
$ go build && sudo ./ebpf-test
go build && sudo ./ebpf-test
2024/12/30 13:15:44 Counting incoming packets on eth0..
2024/12/30 13:15:45 Received 1 packets
2024/12/30 13:15:46 Received 9 packets
2024/12/30 13:15:47 Received 33 packets
2024/12/30 13:15:48 Received 34 packets
2024/12/30 13:15:49 Received 35 packets
^C2024/12/30 13:15:49 Received signal, exiting..
```