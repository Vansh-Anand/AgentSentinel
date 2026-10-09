"""Export one run's public evidence without copying either private signing key."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from .verify_public import verify_public_run


def export_public_run(run_id: str, data_dir: Path, output_dir: Path) -> dict[str, object]:
    safe_id = str(uuid.UUID(run_id))
    public_key = (data_dir / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
    verification = verify_public_run(safe_id, data_dir, public_key)
    if verification.get("valid") is not True:
        raise ValueError(f"source run verification failed: {verification.get('failure', 'unknown')}")
    output_dir.mkdir(parents=True, exist_ok=False)
    for category, suffix in (("runtime-audit", ".jsonl"),
                             ("runtime-receipts", ".json")):
        target_dir = output_dir / category
        target_dir.mkdir()
        source = data_dir / category / f"{safe_id}{suffix}"
        (target_dir / source.name).write_bytes(source.read_bytes())
    (output_dir / "runtime-signing-key.pub").write_text(public_key + "\n", encoding="ascii")
    exported = verify_public_run(safe_id, output_dir, public_key)
    if exported.get("valid") is not True:
        raise ValueError("exported evidence failed public verification")
    return {"run_id": safe_id, "output_dir": str(output_dir),
            "records_checked": exported["records_checked"],
            "key_fingerprint_sha256": exported["key_fingerprint_sha256"],
            "note": "Pin the public key through an independent channel before relying on this bundle."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--data-dir", type=Path, default=Path(".data"))
    args = parser.parse_args()
    try:
        result = export_public_run(args.run_id, args.data_dir, args.output_dir)
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "failure": str(exc)[:120]}))
        return 1
    print(json.dumps({"valid": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
