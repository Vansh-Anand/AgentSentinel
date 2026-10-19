"""Conservative source-to-artifact provenance for the synthetic local lab."""
from __future__ import annotations

import hashlib
import re


CLASSIFICATION_RANK = {
    "SYNTHETIC_PUBLIC": 0,
    "ATTACKER_CONTROLLED_SYNTHETIC": 1,
    "RESTRICTED_SYNTHETIC": 2,
}
SOURCE_REFERENCE = re.compile(r"\bSRC-[A-Z0-9-]+\b")


class ProvenanceLedger:
    """All observed sources are treated as possible parents of later artifacts.

    This intentionally over-approximates derivation. It does not infer whether a
    model actually used a sentence, and never trusts a model-declared label.
    """

    def __init__(self):
        self.sources: dict[str, dict] = {}
        self.artifacts: list[dict] = []
        self.exports: list[dict] = []

    def observe(self, effect: dict) -> None:
        source_id = effect.get("source_id")
        if effect.get("kind") != "file_read" or not isinstance(source_id, str):
            return
        classification = effect.get("classification")
        if classification not in CLASSIFICATION_RANK:
            raise ValueError("UNKNOWN_SOURCE_CLASSIFICATION")
        content_hash = effect.get("sha256")
        if not isinstance(content_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", content_hash):
            raise ValueError("SOURCE_HASH_REQUIRED")
        record = {"source_id": source_id, "path": effect["target"],
                  "classification": classification, "sha256": content_hash}
        prior = self.sources.get(source_id)
        if prior is not None and prior != record:
            raise ValueError("SOURCE_ID_CHANGED_DURING_RUN")
        self.sources[source_id] = record

    def unknown_citations(self, text: str) -> list[str]:
        return sorted(set(SOURCE_REFERENCE.findall(text)) - set(self.sources))

    def derived_classification(self) -> str:
        if not self.sources:
            return "SYNTHETIC_PUBLIC"
        return max((source["classification"] for source in self.sources.values()),
                   key=lambda label: CLASSIFICATION_RANK[label])

    def ticket_allowed(self) -> bool:
        return self.derived_classification() != "RESTRICTED_SYNTHETIC"

    def record_export(self, tool: str, destination: str, decision: str, reason: str) -> dict:
        record = {"tool": tool, "destination": destination, "decision": decision,
                  "reason": reason, "source_ids": sorted(self.sources),
                  "classification": self.derived_classification()}
        self.exports.append(record)
        return record

    def record_artifact(self, effect: dict) -> None:
        if effect.get("kind") not in {"file_write", "ticket_created"}:
            return
        record = {"artifact_id": f"ART-{len(self.artifacts)+1:03d}",
                  "kind": effect["kind"], "target": effect["target"],
                  "sha256": effect["sha256"], "classification": self.derived_classification(),
                  "source_ids": sorted(self.sources)}
        self.artifacts.append(record)

    def snapshot(self) -> dict:
        sources = sorted(self.sources.values(), key=lambda item: item["source_id"])
        edges = [{"source_id": source["source_id"], "artifact_id": artifact["artifact_id"]}
                 for artifact in self.artifacts for source in sources
                 if source["source_id"] in artifact["source_ids"]]
        value = {"schema_version": 1, "derivation": "conservative_run_scope",
                 "sources": sources, "artifacts": self.artifacts.copy(), "edges": edges,
                 "exports": self.exports.copy()}
        # This value is included in the signed run summary. A separate digest
        # makes the provenance binding easy to identify in exported evidence.
        import json
        value["sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        return value
