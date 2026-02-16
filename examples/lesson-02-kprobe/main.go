package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	PID      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("kprobe_unlink.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach kprobe
	prog := coll.Programs["kprobe_unlinkat"]
	if prog == nil {
		log.Fatal("kprobe_unlinkat program not found")
	}

	kp, err := link.Kprobe("do_unlinkat", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	log.Println("kprobe attached. Monitoring unlink() syscalls...")

	// Read from ringbuf
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Setup signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Println("PID\tCOMM\tFILENAME")
	log.Println("---\t----\t--------")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				return
			}

			var e Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
			log.Printf("%d\t%s\t%s\n", e.PID, comm, filename)
		}
	}()

	<-sig
	log.Println("\nDetaching...")
}
