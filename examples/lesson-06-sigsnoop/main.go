package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type SignalData struct {
	Ts       uint64
	SrcPID   uint32
	DstPID   uint32
	Sig      int32
	SrcComm  [16]byte
	DstComm  [16]byte
}

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("sigsnoop.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach to tracepoint
	prog := coll.Programs["trace_signal"]
	if prog == nil {
		log.Fatal("trace_signal program not found")
	}

	tp, err := link.Tracepoint("signal", "signal_generate", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("sigsnoop attached. Monitoring signal generation...")

	// Read from ringbuf
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Setup signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Println("TIME\t\tSRC_PID\tDST_PID\tSIGNAL\tSRC_COMM")
	log.Println("----\t\t-------\t-------\t------\t--------")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				return
			}

			var data SignalData
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
				continue
			}

			t := time.Unix(0, int64(data.Ts)).Format("15:04:05")
			comm := string(bytes.TrimRight(data.SrcComm[:], "\x00"))
			log.Printf("%s\t%d\t%d\t%d\t%s\n", t, data.SrcPID, data.DstPID, data.Sig, comm)
		}
	}()

	<-sig
	log.Println("\nDetaching...")
}
