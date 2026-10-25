"""Single-use trusted lab tool worker for Windows Job or Linux cgroup execution."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from .lab_tools import EXECUTION_LIMIT_REASONS, ExecutionLimit, LabExecutor, LabPolicy


def execute_packet(packet: dict) -> dict:
    policy = LabPolicy(Path(packet["workspace"]), packet["profile"], packet.get("catalog"))
    if policy.policy_hash != packet["policy_sha256"]:
        raise PermissionError("POLICY_HASH_MISMATCH")
    executor = LabExecutor(Path(packet["artifacts"]), packet["untrusted_readme"])
    output = executor.execute(packet["tool"], packet["arguments"], policy)
    return {"output": output, "effects": executor.effects}


def main() -> int:
    # The parent places this input-blocked process in a per-action containment
    # group before sending any authorized action.
    try:
        raw = sys.stdin.buffer.readline(32769)
        if len(raw) > 32768 or not raw.endswith(b"\n"):
            raise ValueError("INVALID_WORKER_PACKET")
        packet = json.loads(raw)
        result = execute_packet(packet)
        sys.stdout.write(json.dumps({"ok": True, **result}, separators=(",", ":")) + "\n")
        return 0
    except Exception as exc:
        error = {"ok": False, "error": type(exc).__name__}
        if isinstance(exc, ExecutionLimit) and str(exc) in EXECUTION_LIMIT_REASONS:
            error["reason"] = str(exc)
        sys.stdout.write(json.dumps(error, separators=(",", ":")) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
