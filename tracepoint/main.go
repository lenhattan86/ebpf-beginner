package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Define event structure (must match the C struct)
type eventT struct {
	PID  uint32
	Comm [16]byte
}

func main() {
	// Load eBPF object file
	spec, err := ebpf.LoadCollectionSpec("trace_exec.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object file: %v", err)
	}

	// Create an eBPF collection from the spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get the eBPF program and map from the collection
	prog := coll.Programs["trace_exec"]
	if prog == nil {
		log.Fatalf("Failed to find eBPF program 'trace_exec'")
	}
	defer prog.Close()

	events := coll.Maps["events"]
	if events == nil {
		log.Fatalf("Failed to find eBPF map 'events'")
	}
	defer events.Close()

	// Attach eBPF program to the tracepoint "sched/sched_process_exec"
	tp, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Set up perf event reader
	reader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v", err)
	}
	defer reader.Close()

	fmt.Println("Listening for exec events...")

	// Capture termination signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Failed to read event: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("Lost %d events", record.LostSamples)
				continue
			}

			var event eventT
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}

			fmt.Printf("Process executed: PID=%d, Comm=%s\n", event.PID, bytes.Trim(event.Comm[:], "\x00"))
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}
