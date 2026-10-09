"""Verify a local gateway run without starting the API server."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from .evidence import verify_chain
from .layer_report import matches_current_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", help="UUID returned by /api/runtime/run")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / ".data")
    parser.add_argument("--check-current-source", action="store_true",
                        help="also compare recorded software hashes with this checkout")
    args = parser.parse_args()
    try:
        run_id = str(uuid.UUID(args.run_id))
    except ValueError:
        parser.error("run_id must be a UUID")
    key_path = args.data_dir / "runtime-audit-key.bin"
    if not key_path.exists():
        print(json.dumps({"valid": False, "failure": "AUDIT_KEY_MISSING"}))
        return 1
    log_path = args.data_dir / "runtime-audit" / f"{run_id}.jsonl"
    result = verify_chain(log_path,
                          args.data_dir / "runtime-anchor" / f"{run_id}.json", key_path.read_bytes())
    if args.check_current_source:
        current = False
        if result["valid"]:
            try:
                for line in reversed(log_path.read_text(encoding="utf-8").splitlines()):
                    event = json.loads(line)["event"]
                    if event.get("event") == "LAYER_REPORT":
                        layers = event.get("layers", [])
                        current = matches_current_source(layers[6]["evidence"])
                        break
            except (OSError, UnicodeError, ValueError, KeyError, IndexError, TypeError):
                current = False
        result["current_source_matches"] = current
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] and (not args.check_current_source or current) else 1


if __name__ == "__main__":
    sys.exit(main())
