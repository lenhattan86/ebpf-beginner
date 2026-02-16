package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Ts       uint64
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
	Ret      int64
}

func main() {
	fmt.Println("Lesson 3: fentry Probes")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("This lesson demonstrates using fentry probes for fast function entry instrumentation.")
	fmt.Println()
	fmt.Println("Build: make build")
	fmt.Println("Run:   make run")
	fmt.Println()
	fmt.Println("The eBPF program (fentry_unlink.c) attaches to the do_unlinkat kernel function")
	fmt.Println("and captures file deletion events using a ring buffer.")
	fmt.Println()
	fmt.Println("TODO: Implement full example with link attachment")
}
