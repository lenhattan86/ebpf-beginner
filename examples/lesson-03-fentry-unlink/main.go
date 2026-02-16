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
	"github.com/cilium/ebpf/rmaps"
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
	spec, err := ebpf.NewCollectionSpec()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["fentry_unlink"]
	if prog == nil {
		log.Fatal("fentry_unlink program not found")
	}

	kp, err := rmaps.Kretprobe("do_unlinkat", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach fentry: %v", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("%-18s %-6s %-6s %-16s %s\n", "TIME", "PID", "UID", "COMM", "FILENAME")

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
			filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
			fmt.Printf("%-18s %-6d %-6d %-16s %s\n", ts, e.Pid, e.Uid, comm, filename)
		}
	}()

	<-sig
	fmt.Println("Exiting...")
}
