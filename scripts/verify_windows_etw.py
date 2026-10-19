"""Probe actual Windows ETW process correlation without starting the website.

Run from an elevated PowerShell or an account in Performance Log Users:
    python scripts/verify_windows_etw.py
The subprocess is an inert Python sleep; no model, files, or network are used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_runtime.windows_etw import EtwActionObserver


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true", help="Write the result to .data/tmp/etw-selftest-result.json")
    args = parser.parse_args()
    temporary_root = Path(__file__).resolve().parents[1] / ".data" / "tmp"
    temporary_root.mkdir(parents=True, exist_ok=True)
    def report(result: dict) -> None:
        print(json.dumps(result, indent=2))
        if args.record:
            (temporary_root / "etw-selftest-result.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8")

    with TemporaryDirectory(prefix="agentsentinel-etw-", dir=temporary_root) as directory:
        observer = EtwActionObserver(Path(directory), "etw-self-test", diagnostic=True)
        started = observer.start()
        if started["status"] != "RECORDING":
            report(started)
            return 2
        launch_ns = time.time_ns()
        try:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            child.wait(timeout=5)
            result = observer.stop(child.pid, launch_ns)
            result["expected_pid"] = child.pid
        except BaseException:
            observer.stop(None, None)
            raise
        report(result)
        return 0 if result["status"] == "CORRELATED_PARTIAL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
