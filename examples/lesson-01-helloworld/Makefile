.PHONY: build run clean all help

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/arm64/arm64/')
OBJDIR := output
OUTPUT := $(OBJDIR)/$(ARCH)

LIBBPF_DIR := /usr/include/bpf
INCLUDES := -I$(LIBBPF_DIR)

CLANG_BPF_SYS_INCLUDES = $(shell clang -mdump-json -x c /dev/null | jq -r '.[] | select(.name | startswith("-I")) | .value')

all: build

vmlinux.h: $(VMLINUX_BTF)
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

build: vmlinux.h $(OUTPUT)/hello.o
	@mkdir -p $(OUTPUT)
	go build -o $(OUTPUT)/hello-demo .

$(OUTPUT)/hello.o: hello.c vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) -O2 -target bpf $(INCLUDES) -c hello.c -o $@

run: build
	sudo $(OUTPUT)/hello-demo

clean:
	rm -rf $(OBJDIR) vmlinux.h

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  build     - Build eBPF object and Go binary"
	@echo "  vmlinux.h - Generate kernel type definitions"
	@echo "  run       - Run the program with sudo"
	@echo "  clean     - Remove build artifacts and vmlinux.h"
	@echo "  help      - Show this help message"

