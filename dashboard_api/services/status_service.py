import os
import sqlite3
from typing import List, Tuple
from dashboard_api.schemas.status import (
    SystemStatusResponse,
    LayerSystemStatus,
    CapabilityStatus,
    InfrastructureStatus
)
from dashboard_api.schemas.pipeline import ExecutionMode

class StatusService:
    @classmethod
    def get_system_status(cls) -> SystemStatusResponse:
        database_status, eces_ok = cls._check_database()
        
        # Determine overall status
        overall_status = "PARTIALLY OPERATIONAL"
        overall_description = (
            f"Research ECES SQLite storage is {database_status.lower()}. "
            "Native eBPF telemetry and hardware attestation are not attached to this deployment. "
            "The gateway's separate signed audit is shown on the Gateway page."
        )

        return SystemStatusResponse(
            api_version="1.0.0",
            backend_status="OPERATIONAL",
            database_status=database_status,
            overall_status=overall_status,
            overall_description=overall_description,
            infrastructure=cls._get_infrastructure(eces_ok),
            layers=cls._get_layers(eces_ok),
            capabilities=cls._get_capabilities(eces_ok)
        )

    @classmethod
    def _check_database(cls) -> Tuple[str, bool]:
        from l6_eces.storage.sqlite_store import DEFAULT_DB_PATH
        db_path = os.environ.get("AGENTSENTINEL_ECES_DB_PATH", DEFAULT_DB_PATH)
        if not os.path.exists(db_path):
            return "UNAVAILABLE", False
        
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("SELECT 1")
            return "OPERATIONAL", True
        except Exception:
            return "ERROR", False

    @classmethod
    def _get_infrastructure(cls, eces_ok: bool) -> List[InfrastructureStatus]:
        return [
            InfrastructureStatus(
                name="Dashboard API",
                status="OPERATIONAL",
                execution_mode=ExecutionMode.REAL_RUNTIME,
                description="Serving REST API for frontend dashboard."
            ),
            InfrastructureStatus(
                name="ECES SQLite Database",
                status="OPERATIONAL" if eces_ok else "UNAVAILABLE",
                execution_mode=ExecutionMode.REAL_RUNTIME if eces_ok else ExecutionMode.UNAVAILABLE,
                description="Research pipeline SQLite evidence storage."
            ),
            InfrastructureStatus(
                name="Pipeline Engine",
                status="OPERATIONAL",
                execution_mode=ExecutionMode.REAL_RUNTIME,
                description="Multi-layer orchestration backend."
            ),
            InfrastructureStatus(
                name="Native Runtime Telemetry",
                status="UNAVAILABLE",
                execution_mode=ExecutionMode.UNAVAILABLE,
                description="Native eBPF kernel probes (Linux only)."
            )
        ]

    @classmethod
    def _get_layers(cls, eces_ok: bool) -> List[LayerSystemStatus]:
        return [
            LayerSystemStatus(
                layer_id="L1",
                name="Grammar-Constrained Decoding",
                operational_status="OPERATIONAL",
                execution_mode=ExecutionMode.REAL_RUNTIME,
                description="Enforces strict schema compliance before LLM execution.",
                capabilities=["GCD", "Pushdown Automaton", "YAML policy compilation", "Policy hot reload"],
                limitations=["Only supports constrained prompt patterns."]
            ),
            LayerSystemStatus(
                layer_id="L2",
                name="Semantic Detection & Normalization",
                operational_status="OPERATIONAL",
                execution_mode=ExecutionMode.REAL_RUNTIME,
                description="Parses, normalizes, and canonicalizes shell commands.",
                capabilities=["Shell parsing", "Normalization", "Canonicalization", "Semantic policy matching"],
                limitations=["Limited to known shell grammar trees."]
            ),
            LayerSystemStatus(
                layer_id="L3",
                name="Runtime Telemetry",
                operational_status="PARTIAL",
                execution_mode=ExecutionMode.SIMULATED,
                description="Replays execution context and OS telemetry for the research demo.",
                capabilities=["JSONL telemetry replay", "ExecutionCorrelationManager"],
                limitations=["No native eBPF collector is attached to this API process."]
            ),
            LayerSystemStatus(
                layer_id="L4",
                name="Behavioral Divergence",
                operational_status="PARTIAL",
                execution_mode=ExecutionMode.SYNTHETIC,
                description="Benchmarks anomaly detection on synthetic traces.",
                capabilities=["Isolation Forest", "Siamese Recurrent Autoencoder", "CUSUM adaptive recalibration"],
                limitations=["Models trained on synthetic benchmarks.", "No real-time continuous deployment active."]
            ),
            LayerSystemStatus(
                layer_id="L5",
                name="Bayesian RiskChain Correlation",
                operational_status="OPERATIONAL",
                execution_mode=ExecutionMode.SIMULATED,
                description="Evaluates attack causal chains and cross-session replay in research mode.",
                capabilities=["RiskChainGraph", "BayesianRiskModel", "GovernanceEngine", "RiskPathAnalyzer", "CrossSessionReplayDetector"],
                limitations=["Evaluated primarily in benchmark modes."]
            ),
            LayerSystemStatus(
                layer_id="L6",
                name="Research ECES Evidence",
                operational_status="OPERATIONAL" if eces_ok else "UNAVAILABLE",
                execution_mode=ExecutionMode.REAL_RUNTIME if eces_ok else ExecutionMode.UNAVAILABLE,
                description="Stores the research pipeline's evidence in SQLite; separate from gateway signed audit.",
                capabilities=["ECES hash chain", "SQLite durable evidence store", "Chain verification utility"],
                limitations=["Single-node deployment without an independent external anchor."] if eces_ok else
                            ["No readable research ECES SQLite database is present in this deployment."]
            ),
            LayerSystemStatus(
                layer_id="L7",
                name="Agent Isolation",
                operational_status="UNAVAILABLE",
                execution_mode=ExecutionMode.UNAVAILABLE,
                description="Native OS-level containment is inactive in this deployment.",
                capabilities=["AgentScopeManager API"],
                limitations=["Native OS-level isolation is not active in this deployment."]
            )
        ]

    @classmethod
    def _get_capabilities(cls, eces_ok: bool) -> List[CapabilityStatus]:
        return [
            CapabilityStatus(
                name="Prompt Injection Defense",
                status="Operational",
                validation_level="Real LLM benchmark",
                execution_mode=ExecutionMode.BENCHMARK
            ),
            CapabilityStatus(
                name="Obfuscated Command Detection",
                status="Operational",
                validation_level="Real LLM benchmark",
                execution_mode=ExecutionMode.BENCHMARK
            ),
            CapabilityStatus(
                name="Runtime Syscall Detection",
                status="Partial",
                validation_level="Telemetry replay",
                execution_mode=ExecutionMode.SIMULATED
            ),
            CapabilityStatus(
                name="Behavioral Divergence",
                status="Operational",
                validation_level="Synthetic benchmark",
                execution_mode=ExecutionMode.SYNTHETIC
            ),
            CapabilityStatus(
                name="RiskChain Detection",
                status="Operational",
                validation_level="Benchmark",
                execution_mode=ExecutionMode.BENCHMARK
            ),
            CapabilityStatus(
                name="ECES Persistence",
                status="Operational" if eces_ok else "Unavailable",
                validation_level="SQLite connection check" if eces_ok else "No readable database",
                execution_mode=ExecutionMode.REAL_RUNTIME if eces_ok else ExecutionMode.UNAVAILABLE
            ),
            CapabilityStatus(
                name="Native eBPF",
                status="Pending",
                validation_level="Not validated",
                execution_mode=ExecutionMode.UNAVAILABLE
            ),
            CapabilityStatus(
                name="Native Process Isolation",
                status="Pending",
                validation_level="Not validated",
                execution_mode=ExecutionMode.UNAVAILABLE
            )
        ]
