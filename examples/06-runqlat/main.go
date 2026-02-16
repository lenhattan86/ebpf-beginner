package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
)

const maxSlots = 64

func main() {
	// Load eBPF collection
	spec, err := ebpf.LoadCollectionSpec("runqlat.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	for i := 0; i < 1; i++ {
		allBuckets := runqlat(spec, 5*time.Second)
		printHistogram(allBuckets, 6875, true)
		// printPercentiles(allBuckets, 6875, []float64{50.0, 95.0, 99.0})
	}

	fmt.Println("\nExiting...")
}

type Histogram struct {
	Bins   []uint64
	Counts []uint64
}

func runqlat(spec *ebpf.CollectionSpec, duration time.Duration) map[uint32]Histogram {
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get maps and programs
	// start := coll.Maps["start"]
	latencyHist := coll.Maps["dist"]
	progSchedSwitch := coll.Programs["sched_switch"]
	progSchedWakeup := coll.Programs["sched_wakeup"]
	progSchedWakeupNew := coll.Programs["sched_wakeup_new"]

	if latencyHist == nil || progSchedSwitch == nil || progSchedWakeup == nil || progSchedWakeupNew == nil {
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

	fmt.Printf("Tracking process run queue latency for %s...\n", duration)

	time.Sleep(duration)

	// Define struct to match eBPF key
	type PidKey struct {
		Id   uint32
		Slot uint32
	}

	var key PidKey
	var value uint32
	iter := latencyHist.Iterate()

	allBuckets := map[uint32]([][]uint64){}
	for iter.Next(&key, &value) {
		allBuckets[key.Id] = append(allBuckets[key.Id], []uint64{uint64(key.Slot), uint64(value)})
	}

	if len(allBuckets) == 0 {
		fmt.Println("No data recorded yet.")
	}

	//sort the buckets
	for _, buckets := range allBuckets {
		sort.Slice(buckets, func(i, j int) bool {
			return buckets[i][0] < buckets[j][0]
		})
	}

	// convert to histograms.
	histograms := map[uint32]Histogram{}
	for pid, buckets := range allBuckets {
		histograms[pid] = Histogram{
			Bins:   make([]uint64, len(buckets)),
			Counts: make([]uint64, len(buckets)),
		}
		for i, b := range buckets {
			histograms[pid].Bins[i] = b[0]
			histograms[pid].Counts[i] = b[1]
		}
	}

	return histograms
}

func printHistogram(histograms map[uint32]Histogram, pid uint32, log2 bool) {

	fmt.Printf("Run Queue Latency Histogram:\n")
	fmt.Println("------------------------")

	for id, histogram := range histograms {
		if pid != 0 && pid != id {
			continue
		}

		fmt.Printf("Pid=%d | Latency (us)  |  Count\n", id)
		for i, _ := range histogram.Bins {
			if log2 {
				start := int(math.Pow(2, float64(histogram.Bins[i])))
				if start == 1 {
					start = 0
				}
				end := int(math.Pow(2, float64(histogram.Bins[i]+1))) - 1
				fmt.Printf("%20s: %10.0d\n", fmt.Sprintf("%d->%d", start, end), histogram.Counts[i])
			} else {
				fmt.Printf("%20d: %10.0d\n", histogram.Bins[i], histogram.Counts[i])
			}
		}
		// fmt.Printf("histogram: %v\n", histogram)
		fmt.Println()
	}

	fmt.Println("------------------------")
}

func printPercentiles(histograms map[uint32]Histogram, pid uint32, percentiles []float64) {

	fmt.Printf("\nRun Queue Latency -- Percentiles\n")
	fmt.Printf(" Pid    ")
	for _, percentile := range percentiles {
		fmt.Printf("| p%0.2f Latency (us) ", percentile)
	}
	fmt.Println()
	fmt.Println("------------------------")

	for id, histogram := range histograms {
		if pid != 0 && id != pid {
			continue
		}

		fmt.Printf("%d    ", id)
		for _, percentile := range percentiles {
			fmt.Printf("|    %10.0d", Percentile(histogram.Bins, histogram.Counts, percentile))
		}
		fmt.Println()
	}

	fmt.Println("------------------------")
}

// Percentile computes the value at the given percentile from the bins and counts.
func Percentile(bins, counts []uint64, percentile float64) uint64 {
	if len(bins) == 0 || len(counts) == 0 || len(bins) != len(counts) || percentile < 0 || percentile > 100 {
		return 0
	}

	// Compute the total count of elements
	var totalCount uint64
	for _, count := range counts {
		totalCount += count
	}

	if totalCount == 0 {
		return 0
	}

	// Compute the rank (position in the cumulative distribution)
	rank := uint64(float64(totalCount) * (percentile / 100.0))

	if rank == 0 {
		return bins[0] // Return the first bin if percentile is very low
	}

	// Iterate to find the corresponding percentile bin
	var cumulativeCount uint64
	for i, count := range counts {
		cumulativeCount += count
		if cumulativeCount >= rank {
			return bins[i] // Return the bin value
		}
	}

	// If we reach here, return the last bin value
	return bins[len(bins)-1]
}

// TestPercentile tests the Percentile function with various cases.
func TestPercentile(t *testing.T) {
	tests := []struct {
		name       string
		bins       []uint64
		counts     []uint64
		percentile float64
		expected   uint64
	}{
		{
			name:       "50th percentile (median)",
			bins:       []uint64{1, 2, 3, 4, 5},
			counts:     []uint64{5, 15, 30, 25, 25},
			percentile: 50.0,
			expected:   3, // The median falls in bin 3
		},
		{
			name:       "90th percentile",
			bins:       []uint64{1, 2, 3, 4, 5},
			counts:     []uint64{5, 15, 30, 25, 25},
			percentile: 90.0,
			expected:   5, // The 90th percentile falls in bin 5
		},
		{
			name:       "0th percentile (minimum value)",
			bins:       []uint64{10, 20, 30},
			counts:     []uint64{1, 3, 5},
			percentile: 0.0,
			expected:   10, // Should return the first bin
		},
		{
			name:       "100th percentile (maximum value)",
			bins:       []uint64{10, 20, 30},
			counts:     []uint64{1, 3, 5},
			percentile: 100.0,
			expected:   30, // Should return the last bin
		},
		{
			name:       "Empty bins and counts",
			bins:       []uint64{},
			counts:     []uint64{},
			percentile: 50.0,
			expected:   0, // Should return 0 for an empty list
		},
		{
			name:       "Single bin",
			bins:       []uint64{42},
			counts:     []uint64{10},
			percentile: 75.0,
			expected:   42, // Only one bin exists
		},
		{
			name:       "Out-of-bound percentile",
			bins:       []uint64{5, 10},
			counts:     []uint64{2, 8},
			percentile: -10.0,
			expected:   0, // Invalid percentiles should return 0
		},
		{
			name:       "Very small percentile",
			bins:       []uint64{1, 2, 3},
			counts:     []uint64{5, 15, 30},
			percentile: 1.0,
			expected:   1, // Should return the first bin
		},
		{
			name:       "Mismatched bins and counts",
			bins:       []uint64{1, 2, 3},
			counts:     []uint64{10, 20}, // One element missing
			percentile: 50.0,
			expected:   0, // Should return 0 due to length mismatch
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Percentile(tt.bins, tt.counts, tt.percentile)
			assert.Equal(t, tt.expected, result, "Expected %v but got %v", tt.expected, result)
		})
	}
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
