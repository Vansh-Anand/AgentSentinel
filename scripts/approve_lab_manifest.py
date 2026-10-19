"""Explicit development/release baseline approval; never called automatically by the API."""
from pathlib import Path
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_runtime.secure_lab import ROOT, MEASURED, MANIFEST

if __name__ == "__main__":
    if "--approve-current-source" not in sys.argv:
        raise SystemExit("Review the source, then run with --approve-current-source to approve this software baseline.")
    value = {"schema": 1, "scope": "approved UTF-8 source text with normalized line endings; not loaded-code or hardware attestation",
             "files": {name: hashlib.sha256((ROOT/name).read_text(encoding="utf-8").encode()).hexdigest() for name in MEASURED}}
    MANIFEST.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
    print(f"Approved {len(MEASURED)} source files in {MANIFEST}")
