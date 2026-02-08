BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Werror

# Paths
GO_CMD ?= go
BPF_OBJ = runqlat.o
BPF_SRC = runqlat.c
GO_SRC = main.go
GO_PROG = "runqlat"

# Output
BPF_OUTPUT = $(BPF_OBJ)

# Default target
all: build

# Compile the eBPF program
$(BPF_OBJ): $(BPF_SRC)
	# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OUTPUT) -I/usr/include

# Run the Go program
build: $(BPF_OUTPUT)
	$(GO_CMD) build -o $(GO_PROG) $(GO_SRC)

# Run the Go program
run: build
	./$(GO_PROG)

# Clean up generated files
clean:
	rm -f $(BPF_OBJ)

