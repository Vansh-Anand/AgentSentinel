"""Verify a downloaded export against a separately trusted public key."""
from pathlib import Path
import argparse
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_runtime.secure_lab import verify_export

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    args = parser.parse_args()
    result = verify_export(json.loads(args.bundle.read_text(encoding="utf-8")), args.trusted_public_key.read_text().strip())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["valid"] else 1)
