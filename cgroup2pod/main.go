package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PodInfo represents relevant information about a Kubernetes pod.
type PodInfo struct {
	CgroupID  string
	Namespace string
	Name      string
	UID       string
}

// ContainerStatus represents the container status from crictl inspectp.
type ContainerStatus struct {
	Info struct {
		RuntimeSpec struct {
			Linux struct {
				CgroupsPath string `json:"cgroupsPath"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			UID       string `json:"uid"`
		} `json:"metadata"`
	} `json:"info"`
}

// getCrictlPods retrieves the list of pod sandbox IDs using crictl.
func getCrictlPods() ([]string, error) {
	cmd := exec.Command("crictl", "pods", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute crictl pods: %w", err)
	}

	// Define a struct matching the expected JSON output
	var result struct {
		Sandboxes []struct {
			ID string `json:"id"`
		} `json:"items"`
	}

	// Parse the JSON output
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse crictl pods output: %w", err)
	}

	// Extract pod IDs
	var podIDs []string
	for _, sandbox := range result.Sandboxes {
		podIDs = append(podIDs, sandbox.ID)
	}

	return podIDs, nil
}

// inspectCrictlPod retrieves detailed information about a pod using crictl inspectp.
func inspectCrictlPod(podID string) (*PodInfo, error) {
	cmd := exec.Command("crictl", "inspectp", podID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect pod %s: %w", podID, err)
	}

	var status ContainerStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("failed to parse inspectp output: %w", err)
	}
	fmt.Println("%v", status)

	// Extract the cgroup ID from cgroupsPath
	cgroupID := extractCgroupID(status.Info.RuntimeSpec.Linux.CgroupsPath)

	return &PodInfo{
		CgroupID:  cgroupID,
		Namespace: status.Info.Metadata.Namespace,
		Name:      status.Info.Metadata.Name,
		UID:       status.Info.Metadata.UID,
	}, nil
}

// extractCgroupID parses the cgroup path to extract the cgroup ID.
func extractCgroupID(cgroupPath string) string {
	// Split the path and extract the last component containing the pod identifier
	parts := strings.Split(cgroupPath, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "kubepods") {
			return part
		}
	}
	return ""
}

func main() {
	// Retrieve the list of pod sandbox IDs.
	podIDs, err := getCrictlPods()
	if err != nil {
		fmt.Printf("Error retrieving pods: %v\n", err)
		os.Exit(1)
	}

	// Build a map of cgroup IDs to pod information.
	cgroupToPodMap := make(map[string]*PodInfo)
	for _, podID := range podIDs {
		podInfo, err := inspectCrictlPod(podID)
		if err != nil {
			fmt.Printf("Error inspecting pod %s: %v\n", podID, err)
			continue
		}
		cgroupToPodMap[podInfo.CgroupID] = podInfo
	}

	// Print the mapping.
	fmt.Println("Cgroup ID to Pod Mapping:")
	for cgroupID, pod := range cgroupToPodMap {
		fmt.Printf("Cgroup ID: %s -> Pod: %s/%s (UID: %s)\n", cgroupID, pod.Namespace, pod.Name, pod.UID)
	}
}
