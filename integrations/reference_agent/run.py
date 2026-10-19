"""Separate-process Gemini agent using AgentSentinel's local capability API.

The client has no file, shell, ticket, or network executor of its own. The
model's proposed tools are sent to the gateway and only its bounded output is
returned to the model. Use synthetic tasks and documents in this local demo.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from agent_runtime.lab_provider import LabProvider, ProviderFailure  # noqa: E402
from agent_runtime.lab_tools import CANARY  # noqa: E402

TERMINAL = {"COMPLETED", "BLOCKED", "STOPPED", "ERROR", "CANCELLED"}


class GatewayError(RuntimeError):
    pass


class GatewayClient:
    def __init__(self, base_url: str):
        if not re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}", base_url):
            raise ValueError("The reference agent only connects to a loopback HTTP API.")
        self.base = base_url + "/api/lab"
        self.opener = build_opener(ProxyHandler({}))
        self.session: str | None = None
        self.capability: str | None = None
        self.capability_nonce: str | None = None

    def request(self, path: str, body: dict | None = None, *, capability: bool = False) -> dict:
        headers = {"Content-Type": "application/json"}
        if capability:
            if not self.capability:
                raise GatewayError("No integration capability is active.")
            headers["X-Lab-Capability"] = self.capability
        elif self.session:
            headers["X-Lab-Session"] = self.session
        request = Request(self.base + path,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers=headers, method="POST" if body is not None else "GET")
        try:
            with self.opener.open(request, timeout=10) as response:
                return json.load(response)
        except HTTPError as exc:
            raise GatewayError(f"Gateway rejected {path}: HTTP {exc.code}") from None
        except (URLError, TimeoutError) as exc:
            raise GatewayError(f"Gateway unavailable during {path}: {type(exc).__name__}") from None

    def open(self) -> None:
        self.session = self.request("/session", {})["token"]
        issued = self.request("/adapter/capabilities", {"role": "incident_analyst",
                                                         "lifetime_seconds": 600})
        self.capability = issued["token"]
        self.capability_nonce = issued["nonce"]

    def close(self) -> None:
        if self.session and self.capability_nonce:
            self.request("/adapter/capabilities/revoke", {"nonce": self.capability_nonce})
        self.capability = None
        self.capability_nonce = None

    def action(self, tool: str, arguments: dict, request_id: str) -> dict:
        started = self.request("/adapter/integration/action", {
            "tool": tool, "arguments": arguments, "client_request_id": request_id,
        }, capability=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            run = self.request("/adapter/integration/runs/" + started["run_id"], capability=True)
            if run["status"] in TERMINAL:
                break
            time.sleep(.25)
        else:
            raise GatewayError(f"Gateway run {started['run_id']} exceeded the client wait.")
        result = run.get("result") or {}
        steps = result.get("steps") or []
        if len(steps) != 1 or steps[0].get("request_id") != started["run_id"] + ":0":
            raise GatewayError("Gateway returned an unexpected action receipt.")
        step = steps[0]
        if result.get("verification", {}).get("valid") is not True:
            raise GatewayError("Gateway evidence verification failed.")
        if step["decision"] == "DENY" and (step["executor_invoked"] or step["effects"]):
            raise GatewayError("Denied proposal produced an unexpected effect.")
        return {"run_id": started["run_id"], "request_id": step["request_id"],
                "status": run["status"], "decision": step["decision"],
                "reason": step["reason"], "executor_invoked": step["executor_invoked"],
                "completed": step["completed"], "signed_evidence_valid": True,
                "source_ids": sorted({effect["source_id"] for effect in step["effects"]
                                      if effect.get("kind") == "file_read" and effect.get("source_id")}),
                "output": result.get("adapter_output", "") if step["completed"] else ""}


def run_agent(gateway: GatewayClient, task: str, document: str = "", turns: int = 6) -> dict:
    provider = LabProvider("gemini", task, "", "task")
    feedback: list[dict[str, object]] = []
    if document:
        feedback.append({"tool": "untrusted_external_document", "arguments": {},
                         "decision": "DATA_ONLY", "output": document[:8000]})
    actions = []
    denied_actions: set[str] = set()
    for index in range(turns):
        turn = provider.turn(task, feedback, index)
        if turn.tool is None:
            if CANARY in turn.message or "DEMO_SECRET=" in turn.message:
                raise GatewayError("Synthetic secret marker withheld from the final answer.")
            return {"status": "COMPLETED", "answer": turn.message, "actions": actions,
                    "answer_verification": "MODEL_TEXT_NOT_FACT_CHECKED",
                    "provider": "gemini", "integration": "separate_process_http_capability"}
        fingerprint = json.dumps([turn.tool.name, turn.tool.arguments], sort_keys=True)
        if fingerprint in denied_actions:
            return {"status": "STOPPED", "answer": "The model repeated a denied action.",
                    "actions": actions, "provider": "gemini",
                    "integration": "separate_process_http_capability"}
        request_id = "reference-" + uuid4().hex
        receipt = gateway.action(turn.tool.name, dict(turn.tool.arguments), request_id)
        actions.append({key: value for key, value in receipt.items() if key != "output"} |
                       {"tool": turn.tool.name})
        feedback.append({"tool": turn.tool.name, "arguments": dict(turn.tool.arguments),
                         "decision": receipt["decision"], "reason": receipt["reason"],
                         "source_ids": receipt["source_ids"],
                         "output": receipt["output"][:8192]})
        if receipt["decision"] == "DENY":
            denied_actions.add(fingerprint)
            # The model can explain the denial, but cannot retry the same
            # forbidden action indefinitely.
            continue
    return {"status": "TURN_LIMIT", "answer": "Agent turn budget exhausted.",
            "actions": actions, "provider": "gemini",
            "integration": "separate_process_http_capability"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a separate Gemini agent through the local gateway")
    parser.add_argument("--api", default="http://127.0.0.1:8008")
    parser.add_argument("--task", required=True)
    parser.add_argument("--document-file", type=Path,
                        help="Optional synthetic lower-trust document supplied to the model")
    args = parser.parse_args()
    if len(args.task.encode()) > 4000:
        parser.error("task exceeds 4000 UTF-8 bytes")
    document = ""
    if args.document_file:
        if args.document_file.stat().st_size > 8000:
            parser.error("document exceeds 8000 bytes")
        document = args.document_file.read_text(encoding="utf-8")
    client = GatewayClient(args.api)
    try:
        client.open()
        print(json.dumps(run_agent(client, args.task, document), indent=2))
    except (GatewayError, ProviderFailure) as exc:
        raise SystemExit(str(exc)) from None
    finally:
        client.close()


if __name__ == "__main__":
    main()
