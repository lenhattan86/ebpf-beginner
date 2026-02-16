package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const maxSlots = 64

func main() {
	// Load eBPF collection
	spec, err := ebpf.LoadCollectionSpec("runqlat.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get maps and programs
	start := coll.Maps["start"]
	latencyHist := coll.Maps["dist"]
	progSchedSwitch := coll.Programs["sched_switch"]
	progSchedWakeup := coll.Programs["sched_wakeup"]
	progSchedWakeupNew := coll.Programs["sched_wakeup_new"]

	if start == nil || latencyHist == nil || progSchedSwitch == nil || progSchedWakeup == nil || progSchedWakeupNew == nil {
		log.Fatalf("Failed to find required eBPF objects")
	}

	// Attach tracepoints
	linkSchedSwitch, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_switch",
		Program: progSchedSwitch,
	})
	if err != nil {
		log.Fatalf("Failed to attach sched_switch: %v", err)
	}
	defer linkSchedSwitch.Close()

	linkSchedWakeup, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_wakeup",
		Program: progSchedWakeup,
	})
	if err != nil {
		log.Fatalf("Failed to attach sched_wakeup: %v", err)
	}
	defer linkSchedWakeup.Close()

	linkSchedWakeupNew, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_wakeup_new",
		Program: progSchedWakeupNew,
	})
	if err != nil {
		log.Fatalf("Failed to attach sched_wakeup_new: %v", err)
	}
	defer linkSchedWakeupNew.Close()

	fmt.Println("Tracking process run queue latency...")

	// Setup signal handler
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// fmt.Printf("Sizeof(PidKey): %d\n", unsafe.Sizeof(PidKey{}))
	// fmt.Printf("Offset of ID: %d\n", unsafe.Offsetof(PidKey{}.Id))
	// fmt.Printf("Offset of Slot: %d\n", unsafe.Offsetof(PidKey{}.Slot))
	// fmt.Printf("Alignof(PidKey): %d\n", unsafe.Alignof(PidKey{}))
	// fmt.Printf("Alignof(Slot): %d\n", unsafe.Alignof(PidKey{}.Slot))

	go func() {
		for range time.Tick(5 * time.Second) {
			printHistogram(latencyHist)
			printP99(latencyHist)
			// printStart(start)
		}
	}()

	<-stop
	fmt.Println("\nExiting...")
}

// Define struct to match eBPF key
type PidKey struct {
	Id      uint32
	ZeroPad uint32
	Slot    uint64
}

func printHistogram(hist *ebpf.Map) {
	allBuckets := map[uint32]([][]uint64){}

	var key PidKey
	var value uint64
	iter := hist.Iterate()
	for iter.Next(&key, &value) {
		allBuckets[key.Id] = append(allBuckets[key.Id], []uint64{key.Slot, value})
	}

	if len(allBuckets) == 0 {
		fmt.Println("No data recorded yet.")
		return
	}

	//sort the buckets
	for _, buckets := range allBuckets {
		sort.Slice(buckets, func(i, j int) bool {
			if buckets[i][0] != buckets[j][0] {
				return buckets[i][0] < buckets[j][0]
			}

			return buckets[i][1] < buckets[j][1]
		})
	}

	fmt.Println("\nRun Queue Latency Histogram:")
	fmt.Println(" Pid    | Latency (us)  |  Count")
	fmt.Println("------------------------")

	for id, buckets := range allBuckets {
		fmt.Printf("Pid=%d \n", id)
		for _, b := range buckets {
			fmt.Printf("%10d:  %d\n", b[0], b[1])
		}
		fmt.Println()
	}

	fmt.Println("------------------------")
}

func printP99(hist *ebpf.Map) {
	allBuckets := map[uint32]([][]uint64){}

	var key PidKey
	var value uint64
	iter := hist.Iterate()
	for iter.Next(&key, &value) {
		allBuckets[key.Id] = append(allBuckets[key.Id], []uint64{key.Slot, value})
	}

	if len(allBuckets) == 0 {
		fmt.Println("No data recorded yet.")
		return
	}

	//sort the buckets
	for _, buckets := range allBuckets {
		sort.Slice(buckets, func(i, j int) bool {
			if buckets[i][0] != buckets[j][0] {
				return buckets[i][0] < buckets[j][0]
			}

			return buckets[i][1] < buckets[j][1]
		})
	}

	fmt.Println("\nRun Queue Latency P99:")
	fmt.Println(" Pid    | P99 Latency (us) ")
	fmt.Println("------------------------")

	for id, buckets := range allBuckets {
		p99 := computeP99(buckets)
		fmt.Printf("%d    |    %10.0f \n", id, p99)
	}

	fmt.Println("------------------------")
}

func computeP99(buckets [][]uint64) float64 {
	if len(buckets) == 0 {
		panic("buckets cannot be empty")
	}

	// Step 1: Compute total count
	totalCount := uint64(0)
	for _, bucket := range buckets {
		totalCount += bucket[1] // bucket[1] is the count
	}

	// Step 2: Find p99 threshold
	threshold := float64(totalCount) * 0.99

	// Step 3: Locate p99 bin
	cumulative := uint64(0)
	var binStart, binEnd, prevCount, currCount uint64

	for i, bucket := range buckets {
		prevCount = cumulative
		cumulative += bucket[1] // bucket[1] is the count
		if float64(cumulative) >= threshold {
			binStart = bucket[0]
			if i+1 < len(buckets) {
				binEnd = buckets[i+1][0] // Next bucket's start is this bin's end
			} else {
				binEnd = binStart * 2 // Assume doubling if no next bin
			}
			currCount = cumulative
			break
		}
	}

	// Step 4: Interpolate p99 value within the bin
	fraction := (threshold - float64(prevCount)) / float64(currCount-prevCount)
	p99 := float64(binStart) + fraction*float64(binEnd-binStart)

	return p99
}

func printStart(start *ebpf.Map) {
	var keys []uint32
	buckets := make(map[uint32]uint64)

	var key uint32
	var value uint64
	iter := start.Iterate()
	for iter.Next(&key, &value) {
		fmt.Println(key, value)
		buckets[key] = uint64(value)
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		fmt.Println("No data recorded in start yet.")
		return
	}
}
