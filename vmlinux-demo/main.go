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

// Define the Go struct to match the eBPF event struct
type SwitchEvent struct {
	PrevPid  uint32
	PrevTgid uint32
	NextPid  uint32
	NextTgid uint32
}

func main() {
	// Load eBPF program from compiled object file
	spec, err := ebpf.LoadCollectionSpec("sched_switch.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Create eBPF collection
	objects := struct {
		SchedSwitch *ebpf.Program `ebpf:"sched_switch"`
		Events      *ebpf.Map     `ebpf:"events"`
	}{}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objects.SchedSwitch.Close()
	defer objects.Events.Close()

	// Attach eBPF program to raw tracepoint
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_switch",
		Program: objects.SchedSwitch,
	})
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Set up perf event reader
	rd, err := perf.NewReader(objects.Events, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	// Handle Ctrl+C for clean exit
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	fmt.Println("Listening for sched_switch events...")

	tgidSet := map[uint32]bool{}

	// Read and print events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("Error reading event: %v", err)
				continue
			}

			var event SwitchEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error decoding event: %v", err)
				continue
			}

			// fmt.Printf("Prev TGID: %d, Prev PID: %d -> Next TGID: %d, Next PID: %d\n",
			// 	event.PrevTgid, event.PrevPid, event.NextTgid, event.NextPid)
			if _, ok := tgidSet[event.NextTgid]; !ok {
				fmt.Printf("TGID: %d\n", event.NextTgid)
				tgidSet[event.NextTgid] = true
			}
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}
