#!/bin/bash
# AcademIQ L3 eBPF Native Preflight Validation Script
# This script ensures the Linux environment is ready for native eBPF deployment.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
FAILED=0

pass() { echo -e "[${GREEN}PASS${NC}] $1"; }
warn() { echo -e "[${YELLOW}WARN${NC}] $1"; }
fail() { echo -e "[${RED}FAIL${NC}] $1"; FAILED=$((FAILED + 1)); }

echo "========================================"
echo "AcademIQ Native Linux Preflight Check"
echo "========================================"

# 1. Root Privileges
if [ "$EUID" -ne 0 ]; then
    fail "eBPF requires root privileges. Please run as root (or use sudo)."
else
    pass "Root privileges detected."
fi

# 2. OS Release
if grep -qi "ubuntu" /etc/os-release; then
    VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    pass "OS is Ubuntu (Version: $VERSION)."
else
    warn "OS is not Ubuntu. AcademIQ L3 is officially validated on Ubuntu 22.04+."
fi

# 3. Kernel Version
KERNEL_VER=$(uname -r)
pass "Kernel Version: $KERNEL_VER"
if dpkg --compare-versions "$(uname -r | cut -d'-' -f1)" "lt" "5.15"; then
    fail "Kernel version < 5.15. eBPF capabilities may be severely limited."
fi

# 4. BTF Support
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    pass "BTF (BPF Type Format) support is available."
else
    fail "BTF support missing (/sys/kernel/btf/vmlinux not found). CORE eBPF will not work."
fi

# 5. Tracepoint filesystem and optional BPF filesystem
if [ -f /sys/kernel/tracing/events/syscalls/sys_enter_execve/id ]; then
    pass "syscall tracepoints are exposed through tracefs."
else
    fail "syscall tracepoints are unavailable; mount tracefs at /sys/kernel/tracing."
fi
if mount | grep -q bpffs; then
    pass "BPF filesystem is mounted."
else
    warn "BPF filesystem is not mounted; this collector uses unpinned maps and does not require it."
fi

# 6. Tools
for tool in clang llvm-strip bpftool python3; do
    if command -v $tool &> /dev/null; then
        pass "$tool is installed."
    else
        fail "$tool is missing."
    fi
done
if command -v bpftool &> /dev/null && ! bpftool version &> /dev/null; then
    fail "bpftool is present but cannot run for this kernel. Install matching linux-tools or use a real bpftool binary."
fi

# 7. Cgroup V2
if mount | grep -q "cgroup2"; then
    pass "Cgroup V2 is enabled and mounted."
else
    fail "Cgroup V2 is not mounted. Scoped native validation cannot run."
fi

echo "========================================"
if [ "$FAILED" -gt 0 ]; then
    echo "Preflight failed: $FAILED required check(s) missing."
    exit 1
fi
echo "Preflight passed."
