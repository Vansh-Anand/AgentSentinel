"""Real gateway demo; distinct from the research pipeline's simulated chat route."""

from pathlib import Path
from io import BytesIO
from datetime import datetime, timezone
import importlib.util
import json
import os
from queue import Empty, Queue
import re
import shlex
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore, Thread
from typing import Literal
import uuid
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from agent_runtime.service import run_demo_task, run_container_demo
from agent_runtime.agent import ToolProposal
from agent_runtime.evidence import verify_chain
from agent_runtime.export_evidence import export_public_run
from agent_runtime.verify_public import verify_public_run
from agent_runtime.local_key import gemini_key_configured
from agent_runtime.service import FIXTURE_README


router = APIRouter()
AUDIT_DIR = Path(__file__).resolve().parents[2] / ".data" / "runtime-audit"
EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v4.json"
SECONDARY_EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v3.json"
FALLBACK_EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v2.json"
LEGACY_EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v1.json"
_LIVE_MODEL_SLOTS = BoundedSemaphore(2)
_SENSITIVE_VALUE = re.compile(r"(?i)\b(api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]+")


class RunRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4000)
    provider: str = "fixture"
    readme_text: str | None = Field(default=None, min_length=1, max_length=16_384)


class ContainerDemoRequest(BaseModel):
    attack: bool = False


class PolicyProbeRequest(BaseModel):
    action: Literal["read_file", "execute_command", "http_post"]
    target: str = Field(min_length=1, max_length=512)


@router.post("/run")
def run_agent_task(request: RunRequest):
    try:
        return run_demo_task(request.task, request.provider, AUDIT_DIR,
                             readme_text=request.readme_text if request.readme_text is not None
                             else FIXTURE_README)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _public_progress(name: str, data: dict[str, object]) -> dict[str, object]:
    """Keep the live trace useful without echoing arbitrary tool arguments."""
    if name != "tool_proposed":
        if name == "model_turn":
            message = str(data.get("message", ""))[:300]
            return {**data, "message": _SENSITIVE_VALUE.sub(r"\1=[redacted]", message)}
        return data
    arguments = data.get("arguments")
    values = arguments if isinstance(arguments, dict) else {}
    tool = str(data.get("tool_name", ""))
    if tool == "read_file":
        target = str(values.get("path", ""))[:160]
    elif tool == "execute_command":
        argv = values.get("argv", [])
        target = " ".join(str(value) for value in argv)[:160] if isinstance(argv, list) else "[invalid argv]"
    elif tool == "http_post":
        parsed = urlsplit(str(values.get("url", "")))
        target = f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"[:160]
    else:
        target = "[unrecognized tool]"
    return {
        "turn": data.get("turn"), "request_id": data.get("request_id"),
        "tool_name": tool, "target": _SENSITIVE_VALUE.sub(r"\1=[redacted]", target),
        "source": str(data.get("source", "agent"))[:40],
    }


@router.post("/run/stream")
def stream_agent_task(request: RunRequest):
    """Emit actual agent and gateway checkpoints, then the signed final run."""
    events: Queue[tuple[str, dict[str, object]]] = Queue(maxsize=128)
    sequence = 0

    def publish(name: str, data: dict[str, object]) -> None:
        nonlocal sequence
        sequence += 1
        frame = {
            "sequence": sequence,
            "at": datetime.now(timezone.utc).isoformat(),
            "data": _public_progress(name, data),
        }
        try:
            events.put((name, frame), timeout=1)
        except Exception:
            # The browser may have disconnected. The bounded worker still
            # completes the authoritative audit and signed receipt.
            pass

    def worker() -> None:
        acquired = False
        try:
            if request.provider in {"gemini", "ollama"}:
                acquired = _LIVE_MODEL_SLOTS.acquire(blocking=False)
                if not acquired:
                    publish("run_error", {"code": "MODEL_BUSY", "message": "Two live model runs are already active. Retry shortly or use fixture replay."})
                    return
            result = run_demo_task(
                request.task, request.provider, AUDIT_DIR,
                readme_text=request.readme_text if request.readme_text is not None else FIXTURE_README,
                progress=publish,
            )
            publish("run_completed", {"result": result})
        except ValueError as exc:
            publish("run_error", {"code": "INVALID_INPUT", "message": str(exc)[:240]})
        except RuntimeError as exc:
            publish("run_error", {"code": "RUN_UNAVAILABLE", "message": str(exc)[:240]})
        except Exception:
            publish("run_error", {"code": "RUN_FAILED", "message": "The run failed. Check the API logs and retry."})
        finally:
            if acquired:
                _LIVE_MODEL_SLOTS.release()

    def frames():
        Thread(target=worker, daemon=True).start()
        while True:
            try:
                name, payload = events.get(timeout=15)
            except Empty:
                yield ": heartbeat\n\n"
                continue
            yield f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n\n"
            if name in {"run_completed", "run_error"}:
                break

    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/provider-status")
def provider_status():
    """Report usable local providers without returning any credential."""
    sdk_installed = (importlib.util.find_spec("google") is not None
                     and importlib.util.find_spec("google.genai") is not None)
    ollama_model = os.environ.get("AGENTSENTINEL_OLLAMA_MODEL", "qwen2.5:3b")
    ollama_available = False
    try:
        request = Request("http://127.0.0.1:11434/api/tags")
        with build_opener(ProxyHandler({})).open(request, timeout=1.5) as response:
            tags = json.loads(response.read(100_000))
        ollama_available = any(item.get("name") == ollama_model for item in tags.get("models", []))
    except (OSError, URLError, ValueError, TypeError, KeyError):
        pass
    return {"fixture_available": True,
            "gemini_key_configured": gemini_key_configured(),
            "gemini_sdk_installed": sdk_installed,
            "gemini_model": os.environ.get("AGENTSENTINEL_GEMINI_MODEL", "gemini-3.5-flash-lite"),
            "ollama_available": ollama_available,
            "ollama_model": ollama_model,
            "workspace": "disposable-synthetic"}


@router.post("/probe")
def run_policy_probe(request: PolicyProbeRequest):
    """Exercise L2 with one manual proposal; no model or arbitrary host files."""
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="probe target cannot be blank")
    try:
        if request.action == "read_file":
            arguments = {"path": target}
        elif request.action == "execute_command":
            arguments = {"argv": shlex.split(target)}
        else:
            arguments = {"url": target, "data": "synthetic-only"}
        return run_demo_task(
            "Evaluate one manually submitted tool proposal.", "probe", AUDIT_DIR,
            readme_text="# Synthetic policy probe\n", proposal=ToolProposal(request.action, arguments),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/container-demo")
def run_restricted_container(request: ContainerDemoRequest):
    try:
        return run_container_demo(request.attack, AUDIT_DIR)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _runtime_run_summary(run_id: str, *, include_events: bool = False) -> dict[str, object]:
    """Return bounded, read-only metadata from one local gateway audit."""
    log_path = AUDIT_DIR / f"{run_id}.jsonl"
    if not log_path.is_file():
        raise HTTPException(status_code=404, detail="run not found")
    try:
        if log_path.stat().st_size > 4_000_000:
            raise ValueError("run evidence too large")
        records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        events = [record["event"] for record in records if isinstance(record.get("event"), dict)]
        report = next((event for event in events if event.get("event") == "LAYER_REPORT"), None)
        decisions = [event for event in events if event.get("event") == "DECISION"]
        results = {event.get("request_id"): event for event in events
                   if event.get("event") == "EXECUTION_RESULT"}
        effects = {event.get("request_id"): event for event in events
                   if event.get("event") == "EFFECTSEAL_RECEIPT"}
        if report is None:
            raise ValueError("run did not reach a signed result")
        layers = report.get("layers", [])
        provider = layers[0].get("evidence", {}).get("provider", "unknown") if layers else "unknown"
        data_dir = AUDIT_DIR.parent
        key = (data_dir / "runtime-audit-key.bin").read_bytes()
        public_key = (data_dir / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
        local_check = verify_chain(log_path, data_dir / "runtime-anchor" / f"{run_id}.json", key)
        public_check = verify_public_run(run_id, data_dir, public_key)
        steps = [{
            "request_id": decision.get("request_id"),
            "tool_name": decision.get("tool_name"),
            "decision": decision.get("decision"),
            "reason_code": decision.get("reason_code"),
            "executed": bool(results.get(decision.get("request_id"), {}).get("executed", False)),
            "effect_verdict": effects.get(decision.get("request_id"), {}).get("verdict"),
        } for decision in decisions]
        summary: dict[str, object] = {
            "run_id": run_id,
            "updated_at": datetime.fromtimestamp(log_path.stat().st_mtime, timezone.utc).isoformat(),
            "provider": provider,
            "outcome": "BLOCKED" if any(step["decision"] == "DENY" for step in steps)
                       else "NO_DENIAL" if steps else "NO_PROPOSAL",
            "tool_calls": len(steps),
            "verified": local_check.get("valid") is True and public_check.get("valid") is True,
            "audit_records": len(records),
        }
        if include_events:
            summary.update({
                "steps": steps,
                "layers": [{"layer": layer.get("layer"), "name": layer.get("name"),
                            "mode": layer.get("mode")} for layer in layers],
                "stop_reason": report.get("stop_reason"),
                "final_message_sha256": report.get("final_message_sha256"),
                "audit_verification": local_check,
                "public_verification": public_check,
            })
        return summary
    except (OSError, UnicodeError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=409, detail="run evidence incomplete or unreadable") from None


@router.get("/runs")
def list_runtime_runs(limit: int = Query(default=10, ge=1, le=50)):
    """Recent signed gateway runs; omit half-written provider-error records."""
    if not AUDIT_DIR.exists():
        return {"runs": []}
    paths = sorted(AUDIT_DIR.glob("*.jsonl"), key=lambda path: path.stat().st_mtime,
                   reverse=True)
    runs = []
    for path in paths:
        try:
            safe_id = str(uuid.UUID(path.stem))
            runs.append(_runtime_run_summary(safe_id))
        except (ValueError, HTTPException, OSError):
            continue
        if len(runs) >= limit:
            break
    return {"runs": runs}


@router.get("/runs/{run_id}")
def get_runtime_run(run_id: str):
    try:
        safe_id = str(uuid.UUID(run_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid run ID") from exc
    return _runtime_run_summary(safe_id, include_events=True)


@router.get("/runs/{run_id}/verify")
def verify_run(run_id: str):
    try:
        safe_id = str(uuid.UUID(run_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid run ID") from exc
    key_path = AUDIT_DIR.parent / "runtime-audit-key.bin"
    if not key_path.exists():
        raise HTTPException(status_code=404, detail="audit key unavailable")
    key = key_path.read_bytes()
    if len(key) != 32:
        raise HTTPException(status_code=503, detail="audit key invalid")
    return verify_chain(AUDIT_DIR / f"{safe_id}.jsonl",
                        AUDIT_DIR.parent / "runtime-anchor" / f"{safe_id}.json", key)


@router.get("/runs/{run_id}/evidence.zip")
def download_public_evidence(run_id: str):
    """Return only verified public artifacts, with a bounded archive size."""
    try:
        safe_id = str(uuid.UUID(run_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid run ID") from exc
    data_dir = AUDIT_DIR.parent
    public_key_path = data_dir / "runtime-signing-key.pub"
    paths = (
        AUDIT_DIR / f"{safe_id}.jsonl",
        data_dir / "runtime-receipts" / f"{safe_id}.json",
        public_key_path,
    )
    try:
        if any(path.stat().st_size > 4_000_000 for path in paths):
            raise HTTPException(status_code=413, detail="evidence bundle too large")
        with TemporaryDirectory() as directory:
            output_dir = Path(directory) / "public"
            export_public_run(safe_id, data_dir, output_dir)
            archive = BytesIO()
            with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
                for path in paths:
                    relative = path.relative_to(data_dir).as_posix()
                    bundle.writestr(relative, (output_dir / relative).read_bytes())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="public evidence verification failed") from exc
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=404, detail="evidence unavailable") from exc
    return Response(content=archive.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="agentsentinel-{safe_id}.zip"'})


@router.get("/evaluation")
def get_model_evaluation():
    """Serve only the sanitized, published summary; never local raw run data."""
    report_path = next((path for path in (EVALUATION_REPORT, SECONDARY_EVALUATION_REPORT,
                                          FALLBACK_EVALUATION_REPORT, LEGACY_EVALUATION_REPORT)
                        if path.exists()), None)
    if report_path is None:
        return {"available": False}
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("schema") != 1 or report.get("mode") != "REAL_MODEL_GATEWAY":
            raise ValueError("invalid public evaluation report")
        keys = (
            "model", "corpus", "corpus_sha256", "attack_cases",
            "attack_cases_with_denied_proposal", "attack_denied_proposals",
            "denied_proposals_executed", "benign_cases", "benign_completed",
            "provider_errors", "audit_chains_verified", "signed_receipts_verified",
            "source_hashes_match_current_checkout", "p50_latency_ms", "p95_latency_ms",
        )
        return {"available": True, "report_version": report_path.stem,
                **{key: report[key] for key in keys},
                "repeats": report.get("repeats"),
                "answer_assertion_method": report.get("answer_assertion_method", "not_scored"),
                "benign_task_success": report.get("benign_task_success"),
                "final_results_bound_to_audit": report.get("final_results_bound_to_audit")}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=503, detail="published evaluation unavailable") from None
