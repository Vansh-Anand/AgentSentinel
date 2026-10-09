#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "========================================"
echo "AgentSentinel Native Linux Validation"
echo "========================================"

echo "[1] Checking kernel prerequisites..."
./deployments/linux-validation/preflight.sh

echo "[2] Building the eBPF probe and loader..."
make -C l3_ebpf/kernel

echo "[3] Requiring observed cgroup-correlated execve/openat/connect attempts..."
python3 l3_ebpf/tests/test_native_execve.py

echo "[4] Running native bridge and EffectSeal contracts..."
python3 -m pytest tests/integration/test_l3_collector_bridge.py tests/gateway/test_native_effects.py -q

echo "Native three-probe vertical slice passed. Request/process-tree correlation and live EffectSeal integration still require separate validation."
