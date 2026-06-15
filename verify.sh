#!/bin/bash
# ─────────────────────────────────────────────────────────────
# NetScan eBPF Verification & Diagnostic Script
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EBPF_DIR="$SCRIPT_DIR/src/NetScan/Platform/Linux/Ebpf"

echo "=== 1. Checking build tools ==="
for cmd in make clang bpftool; do
    if command -v $cmd &> /dev/null; then
        echo "  [OK] $cmd is installed"
    else
        echo "  [MISSING] $cmd is NOT installed (Run: sudo apt install make clang bpftool)"
    fi
done

echo ""
echo "=== 2. Performing Clean eBPF Compilation ==="
if [ -d "$EBPF_DIR" ]; then
    cd "$EBPF_DIR"
    echo "Cleaning old object files..."
    make clean --no-print-directory || true
    echo "Compiling netscan_ebpf.bpf.c..."
    if make --no-print-directory; then
        echo "  [SUCCESS] Compilation succeeded!"
    else
        echo "  [FAILED] Compilation failed."
        exit 1
    fi
else
    echo "ERROR: Ebpf directory not found at $EBPF_DIR"
    exit 1
fi

echo ""
echo "=== 3. Testing eBPF Verification with bpftool ==="
if command -v bpftool &> /dev/null; then
    echo "Attempting to load netscan_ebpf.bpf.o into kernel..."
    # Clean up any stale pin
    sudo rm -f /sys/fs/bpf/netscan 2>/dev/null || true
    
    # Run bpftool load and capture output
    if sudo bpftool prog load netscan_ebpf.bpf.o /sys/fs/bpf/netscan; then
        echo "  [SUCCESS] Kernel accepted eBPF bytecode successfully!"
        sudo rm -f /sys/fs/bpf/netscan
    else
        echo "  [FAILED] Kernel verifier rejected the eBPF bytecode!"
        echo "Please check the verifier output above for the exact rejection reason."
    fi
else
    echo "bpftool is not installed. Trying standard load..."
    echo "Run: sudo apt install linux-tools-common linux-tools-generic to get bpftool."
fi
