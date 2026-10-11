"""Load the demo's per-user Gemini credential without writing plaintext to disk."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


KEY_PATH = Path(__file__).resolve().parents[1] / ".data" / "secrets" / "gemini-key.dpapi"


def gemini_key_configured() -> bool:
    """A configuration indicator, not a provider connectivity or validity check."""
    return bool(os.environ.get("GEMINI_API_KEY")) or (os.name == "nt" and KEY_PATH.is_file())


def load_gemini_key() -> str:
    """Prefer the process environment, then this Windows account's DPAPI blob."""
    direct = os.environ.get("GEMINI_API_KEY")
    if direct:
        return direct
    if os.name != "nt" or not KEY_PATH.is_file():
        raise RuntimeError("Gemini key is not configured on this API host")

    # The command is constant. The path is passed through the child environment,
    # never interpolated into a shell command, and stdout is captured in memory.
    command = (
        "$ErrorActionPreference='Stop'; "
        "$secret=Get-Content -LiteralPath $env:AGENTSENTINEL_KEY_FILE -Raw | ConvertTo-SecureString; "
        "$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret); "
        "try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)) } "
        "finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }"
    )
    try:
        result = subprocess.run(
            ["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=10, check=False,
            env={**os.environ, "AGENTSENTINEL_KEY_FILE": str(KEY_PATH)},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Stored Gemini key requires PowerShell 7 on this API host") from exc
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError("Stored Gemini key could not be opened under this Windows account")
    return result.stdout
