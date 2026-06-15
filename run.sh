#!/bin/bash
# ─────────────────────────────────────────────────────────────
# NetScan v2.0 — Run Script for Linux (RHEL compatible)
# ─────────────────────────────────────────────────────────────
# Usage:
#   chmod +x run.sh
#   sudo ./run.sh              # Interactive menu
#   sudo ./run.sh --live       # Real-time monitoring
#   sudo ./run.sh --snapshot   # Single scan
# ─────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$SCRIPT_DIR/src/NetScan/NetScan.csproj"

# Check if running as root (recommended)
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "  ⚠  WARNING: Not running as root. Process names and PIDs may not resolve."
    echo "  ⚠  Run with: sudo $0 $@"
    echo ""
    sleep 2
fi

# Check for .NET runtime
if ! command -v dotnet &> /dev/null; then
    echo "ERROR: .NET runtime not found. Install .NET 8.0:"
    echo "  RHEL/CentOS: sudo yum install dotnet-runtime-8.0"
    echo "  Ubuntu:      sudo apt install dotnet-runtime-8.0"
    exit 1
fi

# Compiling eBPF bytecode if build tools are present
EBPF_DIR="$SCRIPT_DIR/src/NetScan/Platform/Linux/Ebpf"
if [ -d "$EBPF_DIR" ]; then
    if command -v make &> /dev/null && command -v clang &> /dev/null; then
        echo "Building eBPF bytecode..."
        make -C "$EBPF_DIR" --no-print-directory || echo "Warning: eBPF compilation failed. Will try using existing binary."
    else
        echo "  [WARN] 'make' or 'clang' not found. Skipping eBPF compilation."
        echo "  [WARN] If you made changes to the eBPF C program, install them: sudo apt install make clang"
        sleep 1
    fi
fi

echo "Building NetScan..."
dotnet build "$PROJECT" -c Release --nologo -v q 2>/dev/null

echo "Starting NetScan v2.0..."
dotnet run --project "$PROJECT" -c Release --no-build -- "$@"
