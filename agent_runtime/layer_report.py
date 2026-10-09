"""Truthful seven-stage report bound to actual local run evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .gateway import GatewayResult
from .policy import TaskPolicy
from .risk import RiskAssessment


_MEASURED_SOURCE_FILES = (
    "agent_runtime/agent.py", "agent_runtime/gateway.py", "agent_runtime/policy.py",
    "agent_runtime/risk.py", "agent_runtime/effectseal.py", "agent_runtime/service.py",
    "agent_runtime/providers.py", "agent_runtime/layer_report.py", "agent_runtime/evidence.py",
    "agent_runtime/ledger.py", "agent_runtime/tools.py", "agent_runtime/docker_executor.py",
    "agent_runtime/docker_demo.py", "agent_runtime/signing.py", "agent_runtime/native_effects.py",
    "l3_ebpf/kernel/events.h", "l3_ebpf/kernel/execve.bpf.c",
    "l3_ebpf/userspace/native_loader.c", "l3_ebpf/userspace/collector.py",
    "l3_ebpf/userspace/health.py", "l3_ebpf/namespace/scope.py",
    "l4_divergence/siamese/model.py", "l4_divergence/siamese/train.py",
    "l7_trust/attestation/verifier.py",
)
_INACTIVE_RESEARCH_ARTIFACTS = (
    "config/checkpoints/l4_siamese.pt",
    "config/checkpoints/l4_benign_centroid.pt",
)


def _hash_files(names: tuple[str, ...]) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def software_measurement(policy: TaskPolicy) -> dict[str, object]:
    """Hash local artifacts; this is not a hardware quote or remote attestation."""
    files = _hash_files(_MEASURED_SOURCE_FILES)
    inactive = _hash_files(_INACTIVE_RESEARCH_ARTIFACTS)
    payload = {"schema": 2, "policy_sha256": policy.policy_hash, "files": files,
               "inactive_research_artifacts": inactive}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"digest_sha256": digest, "policy_sha256": policy.policy_hash,
            "file_count": len(files), "files": files,
            "inactive_research_artifacts": inactive, "model_active": False,
            "hardware_attested": False}


def matches_current_source(measurement: Mapping[str, object]) -> bool:
    """Compare recorded disk hashes to this checkout; no loaded-code or hardware proof."""
    files = measurement.get("files")
    inactive = measurement.get("inactive_research_artifacts")
    policy_hash = measurement.get("policy_sha256")
    if not isinstance(files, dict) or set(files) != set(_MEASURED_SOURCE_FILES):
        return False
    if not isinstance(inactive, dict) or set(inactive) != set(_INACTIVE_RESEARCH_ARTIFACTS):
        return False
    if not isinstance(policy_hash, str) or len(policy_hash) != 64:
        return False
    if (measurement.get("file_count") != len(files)
            or measurement.get("hardware_attested") is not False
            or measurement.get("model_active") is not False):
        return False
    try:
        current = _hash_files(_MEASURED_SOURCE_FILES)
        current_inactive = _hash_files(_INACTIVE_RESEARCH_ARTIFACTS)
    except OSError:
        return False
    if files != current or inactive != current_inactive:
        return False
    payload = {"schema": 2, "policy_sha256": policy_hash, "files": current,
               "inactive_research_artifacts": current_inactive}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return measurement.get("digest_sha256") == digest


def build_layer_report(
    *,
    provider: str,
    model: str | None,
    policy: TaskPolicy,
    results: Iterable[GatewayResult],
    risk: RiskAssessment,
    effect_verdicts: Iterable[str],
) -> list[dict[str, object]]:
    observed = tuple(results)
    verdicts = tuple(effect_verdicts)
    allowed = sum(item.decision == "ALLOW" and item.executed for item in observed)
    denied = sum(item.decision == "DENY" for item in observed)
    denied_executed = sum(item.decision == "DENY" and item.executed for item in observed)
    measurement = software_measurement(policy)
    return [
        {"layer": "L1", "name": "Proposal format", "mode": ("REAL_MODEL_STRUCTURED_OUTPUT" if model else
            "FIXED_COMMAND_FIXTURE" if provider == "docker-fixture" else "FIXTURE_REPLAY"),
         "evidence": {"provider": provider, "model": model, "gateway_proposals": len(observed)}},
        {"layer": "L2", "name": "Task policy", "mode": "REAL_RUNTIME",
         "evidence": {"allowed_executed": allowed, "denied": denied,
                      "denied_executed": denied_executed, "policy_sha256": policy.policy_hash}},
        {"layer": "L3", "name": "Native effects", "mode": "UNAVAILABLE",
         "evidence": {"collector": "none", "effectseal_verdicts": list(verdicts),
                      "reason": "No native Linux collector attached to this run"}},
        {"layer": "L4", "name": "Behavior signal", "mode": "REAL_RULE_SIGNAL",
         "evidence": {"score": risk.score, "signals": list(risk.signals),
                      "trained_model": False, "input": "gateway outcomes"}},
        {"layer": "L5", "name": "Risk governance", "mode": "REAL_RUNTIME",
         "evidence": {"action": risk.action, "denied_calls": risk.denied_calls,
                      "incidents": risk.incidents, "stop_threshold": 2}},
        {"layer": "L6", "name": "Audit evidence", "mode": "LOCAL_HMAC_AND_ED25519",
         "evidence": {"algorithm": "HMAC-SHA256 + Ed25519", "external_anchor": False,
                      "offline_verifier": True, "public_key_receipt": True}},
        {"layer": "L7", "name": "Runtime trust", "mode": "SOFTWARE_MEASUREMENT",
         "evidence": measurement},
    ]
