.PHONY: build run clean all

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

build: $(OUTPUT)/fentry_unlink.o
	@mkdir -p $(OUTPUT)
	go build -o $(OUTPUT)/fentry-demo .

$(OUTPUT)/fentry_unlink.o: fentry_unlink.c
	@mkdir -p $(OUTPUT)
	$(CLANG) -O2 -target bpf $(INCLUDES) -c fentry_unlink.c -o $@

run: build
	sudo $(OUTPUT)/fentry-demo

clean:
	rm -rf $(OBJDIR)

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  build     - Build eBPF object and Go binary"
	@echo "  run       - Run the program with sudo"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help message"
