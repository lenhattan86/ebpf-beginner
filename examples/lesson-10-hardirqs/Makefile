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

all: build

vmlinux.h: $(VMLINUX_BTF)
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

build: vmlinux.h $(OUTPUT)/hardirqs.o
	@mkdir -p $(OUTPUT)
	go build -o $(OUTPUT)/hardirqs .

$(OUTPUT)/hardirqs.o: hardirqs.c vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) -O2 -target bpf $(INCLUDES) -c hardirqs.c -o $@

run: build
	sudo $(OUTPUT)/hardirqs

clean:
	rm -rf $(OBJDIR) vmlinux.h

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  build     - Build eBPF object and Go binary"
	@echo "  run       - Run the program with sudo"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help message"
