package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Struct for parsing crictl pods output
type PodSandbox struct {
	ID     string `json:"id"`
	Labels struct {
		PodName      string `json:"io.kubernetes.pod.name"`
		PodNamespace string `json:"io.kubernetes.pod.namespace"`
	} `json:"labels"`
}

// Struct for crictl inspectp output
type PodInspectResponse struct {
	Info struct {
		SandboxMetadata struct {
			Metadata struct {
				Config struct {
					Linux struct {
						CgroupParent string `json:"cgroup_parent"`
					} `json:"linux"`
				} `json:"config"`
			} `json:"Metadata"`
		} `json:"sandboxMetadata"`
	} `json:"info"`
}

// Get all pod sandboxes using crictl pods
func getAllPodSandboxes() ([]PodSandbox, error) {
	cmd := exec.Command("crictl", "pods", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to run crictl pods: %v", err)
	}

	var result struct {
		Items []PodSandbox `json:"items"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("Failed to parse crictl pods output: %v", err)
	}

	return result.Items, nil
}

// listMatchingFolders lists all folders that start with "cri-containerd" in the given directory
func listMatchingFolders(rootDir string) ([]string, error) {
	var matchingFolders []string

	// Compile regex to match folders starting with "cri-containerd"
	regex := regexp.MustCompile(`^cri-containerd.*`)

	// Read directory entries
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}

	// Iterate over entries and filter matching directories
	for _, entry := range entries {
		if entry.IsDir() && regex.MatchString(entry.Name()) {
			matchingFolders = append(matchingFolders, filepath.Join(rootDir, entry.Name()))
		}
	}

	return matchingFolders, nil
}

// GetRootCgroupPath finds the root cgroup mount point (supports both v1 and v2)
func GetRootCgroupPath() (string, error) {
	// Open /proc/mounts to find the cgroup mount point
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("failed to open /proc/mounts: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		mountPoint := fields[1]
		fsType := fields[2]

		// Check for cgroup v2 (unified hierarchy)
		if fsType == "cgroup2" {
			return mountPoint, nil
		}

		// Check for cgroup v1 (separate controllers)
		if fsType == "cgroup" {
			return mountPoint, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /proc/mounts: %v", err)
	}

	return "", fmt.Errorf("cgroup root not found")
}

// Get the full cgroup path for the pod from crictl inspectp
func getCgroupPathForPod(podID string) (string, error) {
	cmd := exec.Command("crictl", "inspectp", podID)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Failed to run crictl inspectp: %v", err)
	}

	var result PodInspectResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("Failed to parse crictl inspectp output: %v", err)
	}

	return result.Info.SandboxMetadata.Metadata.Config.Linux.CgroupParent, nil
}

// Get PIDs from the pod's cgroup path
func getPIDsFromCgroup(cgroupPath string) ([]int, error) {
	rootCgroupPath, err := GetRootCgroupPath()
	if err != nil {
		return nil, fmt.Errorf("Failed to get cgroup path: %v", err)
	}

	paths, err := listMatchingFolders(rootCgroupPath + "/" + cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all the container cgroup paths: %v", err)
	}

	var pids []int
	for _, path := range paths {
		data, err := os.ReadFile(path + "/cgroup.procs")
		if err != nil {
			return nil, fmt.Errorf("Failed to read cgroup.procs: %v", err)
		}

		lines := strings.Split(string(data), "\n")

		for _, line := range lines {
			if line == "" {
				continue
			}
			pid, err := strconv.Atoi(line)
			if err != nil {
				return nil, fmt.Errorf("Failed to convert PID: %v", err)
			}
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

func main() {
	// Step 1: Get all running pod sandboxes
	podSandboxes, err := getAllPodSandboxes()
	if err != nil {
		fmt.Printf("Error retrieving pod sandboxes: %v\n", err)
		return
	}

	// Step 2: Iterate over each pod sandbox and find PIDs
	for _, sandbox := range podSandboxes {
		podID := sandbox.ID
		namespace := sandbox.Labels.PodNamespace
		podName := sandbox.Labels.PodName

		// Step 3: Get the full cgroup path using crictl inspectp
		cgroupPath, err := getCgroupPathForPod(podID)
		if err != nil {
			fmt.Printf("Pod %s/%s (ID: %s): Failed to get cgroup path: %v\n", namespace, podName, podID, err)
			continue
		}

		// Step 4: Get PIDs from the cgroup path
		pids, err := getPIDsFromCgroup(cgroupPath)
		if err != nil {
			fmt.Printf("Pod %s/%s (ID: %s): Failed to get PIDs: %v\n", namespace, podName, podID, err)
			continue
		}

		// Step 5: Print the results
		fmt.Printf("Pod %s/%s (ID: %s) has PIDs: %v\n", namespace, podName, podID, pids)
	}
}
