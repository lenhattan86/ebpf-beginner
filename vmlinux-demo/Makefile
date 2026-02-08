BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Werror -I./headers
LLC ?= llc
GO ?= go

BPF_SRC = sched_switch.c
BPF_OBJ = sched_switch.o
VMLINUX_H = headers/vmlinux.h

all: $(BPF_OBJ) main

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ) 

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

main: main.go $(BPF_OBJ)
	$(GO) build -o main main.go

clean:
	rm -f $(BPF_OBJ) main $(VMLINUX_H)
