package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	PID      uint32
	Comm     [16]byte
	Filename [256]byte
	Flags    int32
}

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("opensnoop.o")
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

	log.Println("opensnoop attached. Monitoring open() syscalls...")

	// Read from ringbuf
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Setup signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Println("PID\tCOMM\t\tFILENAME")
	log.Println("---\t----\t\t--------")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				return
			}

			var e Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}

			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
			log.Printf("%d\t%-16s\t%s\n", e.PID, comm, filename)
		}
	}()

	<-sig
	log.Println("\nDetaching...")
}
