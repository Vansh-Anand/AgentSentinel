"""Credential-safe local capability check for the documented demo paths."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys


def check() -> dict[str, object]:
    image = os.environ.get("AGENTSENTINEL_DOCKER_IMAGE", "")
    pinned = bool(re.fullmatch(r"(?:[a-zA-Z0-9._/-]+@)?sha256:[0-9a-f]{64}", image))
    docker_cli = shutil.which("docker") is not None
    docker_engine = False
    if docker_cli:
        try:
            probe = subprocess.run(
                ["docker", "info", "--format", "{{.OSType}}"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            docker_engine = probe.returncode == 0 and probe.stdout.strip() == "linux"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {
        "python": sys.version.split()[0],
        "platform": platform.system(),
        "fixture_gateway_ready": sys.version_info >= (3, 11),
        "api_dependencies_ready": importlib.util.find_spec("fastapi") is not None
        and importlib.util.find_spec("uvicorn") is not None,
        "gemini_ready": bool(os.environ.get("GEMINI_API_KEY"))
        and importlib.util.find_spec("google") is not None
        and importlib.util.find_spec("google.genai") is not None,
        "docker_cli_available": docker_cli,
        "docker_linux_engine_available": docker_engine,
        "docker_pinned_image_configured": pinned,
        "native_ebpf_attached": False,
        "hardware_attestation_available": False,
    }


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
