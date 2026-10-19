"""Exercise the same HTTP adapter used by the optional Flowise custom tool.

This checks AgentSentinel's adapter contract, not an external Flowise canvas.
"""
from __future__ import annotations

import json
import os
import time
from urllib.request import Request, urlopen

BASE = os.environ.get("AGENTSENTINEL_API_BASE_URL", "http://127.0.0.1:8008").rstrip("/") + "/api/lab"


def call(path: str, token: str | None = None, payload: dict | None = None,
         capability: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Lab-Session"] = token
    if capability:
        headers["X-Lab-Capability"] = capability
    request = Request(BASE + path, data=json.dumps(payload).encode() if payload is not None else None,
                      headers=headers, method="POST" if payload is not None else "GET")
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def run_action(capability: str, path: str, suffix: str) -> dict:
    started = call("/adapter/integration/action", payload={"tool": "read_file", "arguments": {"path": path},
        "client_request_id": "flowise-contract-" + suffix}, capability=capability)
    for _ in range(60):
        run = call("/adapter/integration/runs/" + started["run_id"], capability=capability)
        if run["status"] in {"COMPLETED", "BLOCKED", "STOPPED", "ERROR", "CANCELLED"}:
            step = run["result"]["steps"][-1]
            return {"run_id": started["run_id"], "request_id": step["request_id"],
                "status": run["status"], "reason": run["result"]["reason"],
                "decision": step["decision"], "executor_invoked": step["executor_invoked"],
                "signed_evidence_valid": run["result"]["verification"]["valid"]}
        time.sleep(.25)
    raise TimeoutError(started["run_id"])


if __name__ == "__main__":
    token = call("/session", payload={})["token"]
    capability = call("/adapter/capabilities", token, {"role": "incident_analyst"})["token"]
    suffix = str(time.time_ns())
    allowed = run_action(capability, "README.md", suffix + "-allow")
    denied = run_action(capability, ".env", suffix + "-deny")
    assert allowed["decision"] == "ALLOW" and allowed["executor_invoked"]
    assert denied["decision"] == "DENY" and not denied["executor_invoked"]
    assert denied["reason"] == "PATH_OUT_OF_SCOPE"
    assert allowed["signed_evidence_valid"] and denied["signed_evidence_valid"]
    print(json.dumps({"scope": "LOCAL_ADAPTER_CONTRACT_NOT_FLOWISE_CANVAS",
                      "allowed": allowed, "denied": denied}, indent=2))
