"""Real gateway demo; distinct from the research pipeline's simulated chat route."""

from pathlib import Path
from io import BytesIO
import json
from tempfile import TemporaryDirectory
import uuid
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from agent_runtime.service import run_demo_task, run_container_demo
from agent_runtime.evidence import verify_chain
from agent_runtime.export_evidence import export_public_run


router = APIRouter()
AUDIT_DIR = Path(__file__).resolve().parents[2] / ".data" / "runtime-audit"
EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v3.json"
SECONDARY_EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v2.json"
FALLBACK_EVALUATION_REPORT = Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "agentsentinel_model_eval_v1.json"


class RunRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4000)
    provider: str = "fixture"


class ContainerDemoRequest(BaseModel):
    attack: bool = False


@router.post("/run")
def run_agent_task(request: RunRequest):
    try:
        return run_demo_task(request.task, request.provider, AUDIT_DIR)
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
                                          FALLBACK_EVALUATION_REPORT) if path.exists()), None)
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
