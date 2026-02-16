package main

import (
	"bytes"
	"encoding/binary"
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
	Ts    uint64
	Pid   uint32
	Cpu   uint32
	Delta uint64
	Comm  [16]byte
}

func main() {
	spec, err := ebpf.NewCollectionSpec()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("%-18s %-6s %-6s %-8s %-16s\n", "TIME", "PID", "CPU", "LATENCY_US", "COMM")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Fatalf("Failed to read ringbuf: %v", err)
			}

			var e event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			ts := time.Unix(0, int64(e.Ts)).Format("15:04:05.000000")
			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			fmt.Printf("%-18s %-6d %-6d %-8d %-16s\n", ts, e.Pid, e.Cpu, e.Delta, comm)
		}
	}()

	<-sig
	fmt.Println("Exiting...")
}
