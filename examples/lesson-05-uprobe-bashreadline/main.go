package main

import (
	"fmt"
)

type event struct {
	Ts    uint64
	Pid   uint32
	Uid   uint32
	Comm  [16]byte
	Input uint64
}

func main() {
	fmt.Println("Lesson 5: Userspace Probes (Uprobe)")
	fmt.Println("====================================")
	fmt.Println()
	fmt.Println("This lesson demonstrates attaching eBPF programs to userspace function calls.")
	fmt.Println("Using uprobes, we can intercept library function calls like readline().")
	fmt.Println()
	fmt.Println("Build: make build")
	fmt.Println("Run:   make run")
	fmt.Println()
	fmt.Println("The eBPF program (uprobe_readline.c) attaches to the readline function")
	fmt.Println("in the bash shell and captures keystrokes/input patterns.")
	fmt.Println()
	fmt.Println("TODO: Implement full example with uprobe attachment")
}
