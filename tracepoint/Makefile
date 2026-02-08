BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf
GO = go

BPF_PROG = trace_exec.o
GO_PROG = main

all: $(BPF_PROG) $(GO_PROG)

# Compile eBPF program
$(BPF_PROG): trace_exec.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile Go program
$(GO_PROG): main.go
	$(GO) build -o $(GO_PROG) $<

# Run the program with sudo (required for eBPF)
run: all
	sudo ./$(GO_PROG)

# Clean up compiled files
clean:
	rm -f $(BPF_PROG) $(GO_PROG)
