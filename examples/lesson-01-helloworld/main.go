package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("hello.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach to tracepoint
	prog := coll.Programs["trace_openat"]
	if prog == nil {
		log.Fatal("trace_openat program not found")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached. Monitoring /usr/bin ...")
	log.Println("(Check kernel ring buffer with: sudo cat /sys/kernel/debug/tracing/trace_pipe)")

	// Setup signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("\nDetaching...")
}
