package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

// GetAllPodsPIDs retrieves all pod PIDs from containerd
func GetAllPodsPIDs(socketPath string) (map[string][]int, error) {
	// Connect to containerd
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to containerd: %w", err)
	}
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	// List all containers in containerd
	containers, err := client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Map to store Pod UID → PIDs
	podPIDs := make(map[string][]int)

	for _, container := range containers {
		// Get container metadata
		info, err := container.Info(ctx)
		if err != nil {
			log.Printf("Skipping container %s: %v\n", container.ID(), err)
			continue
		}

		// Extract Pod UID
		podUID, hasUID := info.Labels["io.kubernetes.pod.uid"]
		if !hasUID {
			continue // Skip if not a Kubernetes pod
		}

		// Get container's main process PID
		task, err := container.Task(ctx, nil)
		if err != nil {
			log.Printf("Skipping container %s: %v\n", container.ID(), err)
			continue
		}

		// Store PIDs for each Pod UID
		podPIDs[podUID] = append(podPIDs[podUID], int(task.Pid()))
	}

	if len(podPIDs) == 0 {
		return nil, fmt.Errorf("no running pods found")
	}

	return podPIDs, nil
}

func main() {
	// Define CLI argument for containerd socket path
	socketPath := flag.String("socket", "/run/containerd/containerd.sock", "Path to containerd socket")
	flag.Parse()

	podPIDs, err := GetAllPodsPIDs(*socketPath)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println("Pod UID -> PIDs:")
	for uid, pids := range podPIDs {
		fmt.Printf("%s -> %v\n", uid, pids)
	}
}
