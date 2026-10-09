"""Credential-free end-to-end check of the running Compose API and UI."""

from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.request import Request, urlopen
from zipfile import ZipFile

from agent_runtime.verify_public import verify_public_run


API = f"http://127.0.0.1:{int(os.environ.get('AGENTSENTINEL_API_PORT', '8000'))}"
UI = f"http://127.0.0.1:{int(os.environ.get('AGENTSENTINEL_UI_PORT', '5173'))}"


def fetch(url: str, *, payload: dict[str, object] | None = None) -> bytes:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body,
                      headers={"Content-Type": "application/json"} if body else {})
    with urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP status {response.status}: {url}")
        return response.read()


def wait_ready(url: str, *, seconds: int = 90) -> bytes:
    deadline = time.monotonic() + seconds
    while True:
        try:
            return fetch(url)
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"service did not become ready: {url}") from None
            time.sleep(2)


def main() -> int:
    wait_ready(f"{API}/api/health")
    page = wait_ready(f"{UI}/gateway")
    if b'id="root"' not in page:
        raise RuntimeError("gateway UI did not serve the application shell")

    run = json.loads(fetch(f"{API}/api/runtime/run", payload={
        "task": "Summarize README.md", "provider": "fixture",
    }))
    decisions = [step["decision"] for step in run["steps"]]
    if decisions != ["ALLOW", "DENY"] or run["steps"][1]["executed"]:
        raise RuntimeError("gateway did not allow README and deny the synthetic secret")
    if ([step["effectseal"]["verdict"] for step in run["steps"]]
            != ["INCOMPLETE", "NOT_EXECUTED"]):
        raise RuntimeError("EffectSeal overstated coverage or missed a denied action")
    if run["layers"][2]["mode"] != "UNAVAILABLE" or run["layers"][6]["evidence"]["hardware_attested"]:
        raise RuntimeError("native or hardware layer was incorrectly reported as active")
    if run["audit_verification"]["valid"] is not True or run["signed_receipt"]["valid"] is not True:
        raise RuntimeError("run evidence did not verify")
    run_id = run["run_id"]
    remote_check = json.loads(fetch(f"{API}/api/runtime/runs/{run_id}/verify"))
    if remote_check["valid"] is not True:
        raise RuntimeError("API audit verifier rejected the run")

    archive_bytes = fetch(f"{API}/api/runtime/runs/{run_id}/evidence.zip")
    with tempfile.TemporaryDirectory(prefix="agentsentinel-compose-smoke-") as directory:
        root = Path(directory)
        with ZipFile(BytesIO(archive_bytes)) as bundle:
            expected = {
                f"runtime-audit/{run_id}.jsonl",
                f"runtime-receipts/{run_id}.json",
                "runtime-signing-key.pub",
            }
            if set(bundle.namelist()) != expected:
                raise RuntimeError("evidence archive contains unexpected files")
            for name in expected:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(name))
        public_key = (root / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
        # This verifies bundle consistency; pin the key separately for identity trust.
        verified = verify_public_run(run_id, root, public_key)
        if verified["valid"] is not True:
            raise RuntimeError(f"offline public verification failed: {verified}")
    print(json.dumps({"run_id": run_id, "decisions": decisions,
                      "audit_records": remote_check["records_checked"],
                      "public_receipt_valid": True, "ui_served": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # Public CI exposes annotations even when job logs require sign-in.
            detail = str(exc).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")[:240]
            print(f"::error title=Compose smoke::{type(exc).__name__}: {detail}", flush=True)
        raise
