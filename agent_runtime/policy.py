"""Small, explicit policy for the first real AgentSentinel tool boundary.

Only exact, task-authorized file paths can be read. Commands and network calls
remain disabled until their sandboxed executors exist.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping


def normalize_relative_path(value: object) -> str | None:
    """Reject paths whose meaning depends on OS or path normalization rules."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    if value.startswith("/") or ":" in value:
        return None
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    normalized = PurePosixPath(value).as_posix()
    return normalized if normalized == value else None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str


@dataclass(frozen=True)
class TaskPolicy:
    workspace: Path
    allowed_read_paths: tuple[str, ...]
    max_read_bytes: int = 65_536
    allowed_commands: tuple[tuple[str, ...], ...] = ()
    read_content_sha256: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        root = Path(self.workspace).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace must be an existing directory")
        if not self.allowed_read_paths:
            raise ValueError("at least one read path must be explicitly allowed")
        if self.max_read_bytes <= 0:
            raise ValueError("max_read_bytes must be positive")
        paths = tuple(self.allowed_read_paths)
        if any(normalize_relative_path(path) != path for path in paths):
            raise ValueError("allowed_read_paths must contain normalized relative paths")
        if any(not isinstance(argv, (tuple, list)) or not argv or any(
            not isinstance(part, str) or not part or "\x00" in part for part in argv
        ) for argv in self.allowed_commands):
            raise ValueError("allowed_commands must contain nonempty argument vectors")
        digests = tuple(self.read_content_sha256)
        if any(not isinstance(item, (tuple, list)) or len(item) != 2
               or not isinstance(item[0], str) or not isinstance(item[1], str)
               or item[0] not in paths or not re.fullmatch(r"[0-9a-f]{64}", item[1])
               for item in digests):
            raise ValueError("read_content_sha256 needs allowed paths and lowercase SHA-256 digests")
        if len({item[0] for item in digests}) != len(digests):
            raise ValueError("duplicate read_content_sha256 path")
        object.__setattr__(self, "workspace", root)
        object.__setattr__(self, "allowed_read_paths", paths)
        object.__setattr__(self, "allowed_commands", tuple(tuple(argv) for argv in self.allowed_commands))
        object.__setattr__(self, "read_content_sha256", tuple((path, digest) for path, digest in digests))

    @property
    def policy_hash(self) -> str:
        payload = {
            "schema": 1,
            "workspace": str(self.workspace),
            "allowed_read_paths": sorted(set(self.allowed_read_paths)),
            "max_read_bytes": self.max_read_bytes,
            "allowed_commands": [list(argv) for argv in self.allowed_commands],
            "read_content_sha256": dict(sorted(self.read_content_sha256)),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def decide(self, tool_name: object, arguments: object) -> PolicyDecision:
        if tool_name not in ("read_file", "execute_command", "http_post"):
            return PolicyDecision(False, "UNKNOWN_TOOL")
        if not isinstance(arguments, Mapping):
            return PolicyDecision(False, "INVALID_ARGUMENTS")
        if tool_name == "execute_command":
            if not self.allowed_commands:
                return PolicyDecision(False, "COMMAND_EXECUTION_DISABLED")
            if set(arguments) != {"argv"} or not isinstance(arguments["argv"], list) or not all(
                isinstance(part, str) for part in arguments["argv"]
            ):
                return PolicyDecision(False, "INVALID_ARGUMENTS")
            if tuple(arguments["argv"]) not in self.allowed_commands:
                return PolicyDecision(False, "COMMAND_OUT_OF_SCOPE")
            return PolicyDecision(True, "TASK_POLICY_ALLOW")
        if tool_name == "http_post":
            return PolicyDecision(False, "NETWORK_EXECUTION_DISABLED")
        if set(arguments) != {"path"}:
            return PolicyDecision(False, "INVALID_ARGUMENTS")
        path = normalize_relative_path(arguments["path"])
        if path is None:
            return PolicyDecision(False, "INVALID_PATH")
        if path not in self.allowed_read_paths:
            return PolicyDecision(False, "PATH_OUT_OF_SCOPE")
        return PolicyDecision(True, "TASK_POLICY_ALLOW")
