# AgentSentinel native Linux validation

This profile validates `execve`, `openat`, and IPv4/IPv6 `connect` entry probes on a **native Linux host**. Docker Desktop on Windows cannot prove host-wide Linux telemetry. The probes record attempts, not syscall outcomes, and are not yet connected to Gateway EffectSeal receipts.

The same vertical-slice script passed in a privileged Docker Desktop Linux VM after mounting tracefs inside the disposable container. That is evidence that the probes attach and emit the three targeted events in the VM; it does not substitute for native host or application process-tree validation.

To reproduce that VM-only check in a disposable Docker Desktop environment:

```bash
docker build -f deployments/linux-validation/Dockerfile -t agentsentinel-l3-build .
docker run --rm --privileged --entrypoint /bin/bash agentsentinel-l3-build \
  -lc 'mount -t tracefs tracefs /sys/kernel/tracing && ./deployments/linux-validation/run-benchmarks.sh'
```

`--privileged` grants broad access to the Docker Linux VM. Use this command only in an isolated test environment; the normal API/UI Compose stack does not use it.

## Requirements
- Ubuntu 22.04+ or compatible Linux (Kernel >= 5.15, ideally 6.x).
- Root privileges (`CAP_SYS_ADMIN` and `CAP_BPF`).
- Mounted tracefs at `/sys/kernel/tracing` and cgroups v2. bpffs is optional for the current unpinned maps.
- `clang`, `llvm`, and `libbpf` headers.

## Deployment Steps

### 1. Setup the Environment
On your native Linux target, clone the repository and navigate into it:
```bash
git clone https://github.com/Vansh-Anand/AgentSentinel.git
cd AgentSentinel
```

Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-generic make python3-pip python3-venv
```

### 2. Python Virtual Environment
Create and activate a virtual environment:
```bash
python3 -m venv .data/venv
source .data/venv/bin/activate
python -m pip install -r requirements-test.txt
```

### 3. Run Preflight Validation
Execute the preflight script to ensure your environment is fully capable of running L3 native eBPF:
```bash
sudo ./deployments/linux-validation/preflight.sh
```
Or use the CLI:
```bash
sudo python -m cli.main l3 doctor
```

All required checks (BTF, kernel, tracefs, and cgroups v2) should emit `[PASS]`.
If syscall tracepoints are missing, mount tracefs before rerunning: `sudo mount -t tracefs tracefs /sys/kernel/tracing`.

### 4. Running validation
Use a root shell with the virtual environment activated so the probe can attach:
```bash
sudo -s
source .data/venv/bin/activate
./deployments/linux-validation/run-benchmarks.sh
```

The script fails unless the current cgroup is registered in the BPF filter and correlated `/bin/echo` `execve`, synthetic-file `openat`, and loopback `connect` attempts arrive with zero measured ring-buffer drops. It does **not** complete L3: unique request/process-tree correlation, syscall outcomes, path resolution, and live EffectSeal integration remain separate gates.

### Note on Windows Hosts
Running this directly under Windows is unsupported. WSL2 or a Linux container is not a substitute for validating host-wide native Linux coverage.
