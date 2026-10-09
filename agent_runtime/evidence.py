"""HMAC chained gateway audit for the local runtime.

This is symmetric authentication with a host-held key, not a public signature or
remote transparency anchor. It detects edited, reordered, or truncated records
against an anchor kept outside the agent's disposable workspace.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Mapping


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            key = os.urandom(32)
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            path.chmod(0o600)
        return key
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("audit key must be 32 bytes")
        return key


def verify_chain(log_path: Path, anchor_path: Path, key: bytes) -> dict[str, object]:
    if len(key) != 32:
        raise ValueError("audit key must be 32 bytes")
    if not log_path.exists() or not anchor_path.exists():
        return {"valid": False, "records_checked": 0, "failure": "EVIDENCE_MISSING"}
    previous = "0" * 64
    count = 0
    try:
        for line in log_path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if (not isinstance(record, dict) or set(record) != {"sequence", "previous_mac", "event", "mac"}
                    or record.get("sequence") != count + 1 or record.get("previous_mac") != previous):
                return {"valid": False, "records_checked": count, "failure": "CHAIN_BROKEN"}
            payload = {"sequence": record["sequence"], "previous_mac": record["previous_mac"],
                       "event": record["event"]}
            expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(record.get("mac", "")), expected):
                return {"valid": False, "records_checked": count, "failure": "MAC_INVALID"}
            previous = expected
            count += 1
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
        if anchor != {"sequence": count, "head_mac": previous}:
            return {"valid": False, "records_checked": count, "failure": "ANCHOR_MISMATCH"}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return {"valid": False, "records_checked": count, "failure": "EVIDENCE_MALFORMED"}
    return {"valid": True, "records_checked": count, "head_mac": previous}


class HmacChainedAuditSink:
    def __init__(self, log_path: Path, anchor_path: Path, key: bytes):
        if len(key) != 32:
            raise ValueError("audit key must be 32 bytes")
        self.log_path = log_path
        self.anchor_path = anchor_path
        self.key = key
        self._lock = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        anchor_path.parent.mkdir(parents=True, exist_ok=True)
        if not log_path.exists() and not anchor_path.exists():
            log_path.touch(exist_ok=False)
            self._write_anchor(0, "0" * 64)
        elif not verify_chain(log_path, anchor_path, key)["valid"]:
            raise ValueError("existing audit chain is invalid")

    def _write_anchor(self, sequence: int, head_mac: str) -> None:
        temporary = self.anchor_path.with_suffix(".tmp")
        with temporary.open("wb") as stream:
            stream.write(_canonical({"sequence": sequence, "head_mac": head_mac}))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.anchor_path)

    def append(self, event: Mapping[str, object]) -> None:
        with self._lock:
            verification = verify_chain(self.log_path, self.anchor_path, self.key)
            if not verification["valid"]:
                raise OSError("audit chain verification failed")
            sequence = int(verification["records_checked"]) + 1
            previous = str(verification["head_mac"])
            payload = {"sequence": sequence, "previous_mac": previous, "event": dict(event)}
            mac = hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()
            record = {**payload, "mac": mac}
            with self.log_path.open("ab") as stream:
                stream.write(_canonical(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._write_anchor(sequence, mac)
