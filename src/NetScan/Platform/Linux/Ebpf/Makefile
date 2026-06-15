# ───────────────────────────────────────────────────────────────
# NetScan eBPF Build Script
# Compiles the eBPF C program using clang + BPF CO-RE
#
# Prerequisites:
#   - clang >= 11 (with BPF target support)
#   - libbpf-dev / libbpf-devel
#   - bpftool (for generating vmlinux.h)
#   - linux-headers or kernel-devel package
#
# Usage:
#   make              # Build the eBPF object file
#   make vmlinux      # Generate vmlinux.h from current kernel BTF
#   make clean        # Remove build artifacts
# ───────────────────────────────────────────────────────────────

CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Output
OUTPUT     := netscan_ebpf.bpf.o
VMLINUX    := vmlinux.h

# Compiler flags for eBPF
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Include paths
# libbpf headers are typically in /usr/include/bpf/ or /usr/include/
INCLUDES   := -I. -I/usr/include/bpf

.PHONY: all clean vmlinux

all: $(VMLINUX) $(OUTPUT)

# Generate vmlinux.h from the running kernel's BTF data
# This provides all kernel type definitions for BPF CO-RE
$(VMLINUX):
	@echo "  [VMLINUX] Generating vmlinux.h from kernel BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
		echo "  [VMLINUX] Generated $(VMLINUX) successfully"; \
	else \
		echo "  [ERROR] /sys/kernel/btf/vmlinux not found."; \
		echo "  [ERROR] Kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y"; \
		echo "  [ERROR] Try: sudo apt install linux-headers-$$(uname -r)"; \
		exit 1; \
	fi

# Compile the eBPF C program to BPF bytecode
$(OUTPUT): netscan_ebpf.bpf.c $(VMLINUX)
	@echo "  [BPF]    Compiling $< → $@"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "  [BPF]    Build successful: $(OUTPUT)"
	@echo ""
	@echo "  Deploy this file alongside the NetScan .NET binary."
	@echo "  It will be loaded at runtime via libbpf when --ebpf is used."

clean:
	@echo "  [CLEAN]  Removing build artifacts..."
	rm -f $(OUTPUT) $(VMLINUX)

vmlinux: $(VMLINUX)

# Helper target to verify the build
verify: $(OUTPUT)
	@echo "  [VERIFY] Inspecting eBPF object file..."
	$(BPFTOOL) prog dump xlated pinned /sys/fs/bpf/netscan 2>/dev/null || true
	readelf -S $(OUTPUT) | grep -E "kprobe|tracepoint|maps"
	@echo "  [VERIFY] Sections found in $(OUTPUT):"
	llvm-objdump -h $(OUTPUT) 2>/dev/null || objdump -h $(OUTPUT)
