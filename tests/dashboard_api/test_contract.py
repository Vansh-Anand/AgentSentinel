from fastapi.testclient import TestClient
from dashboard_api.main import app
from dashboard_api.schemas.common import ExecutionMode
from unittest.mock import patch
from common.schemas.security import SecurityDecision, DecisionEnum
import time

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@patch("dashboard_api.services.pipeline_service.AcademiqOrchestrator")
def test_pipeline_safe_scenario(mock_orchestrator_class):
    # Mock the orchestrator to return ALLOW to verify the service correctly structures it
    mock_instance = mock_orchestrator_class.return_value
    mock_instance.session_id = "test-session"
    mock_instance.process_event.return_value = SecurityDecision(
        decision=DecisionEnum.ALLOW,
        reason_codes=[],
        risk_score=5.0,
        confidence=0.99,
        source_layers=["L1", "L2", "L3", "L4", "L5"],
        related_event_ids=[],
        timestamp_ns=time.time_ns()
    )

    response = client.post("/api/pipeline/run", json={"scenario_id": "L7_ATTESTATION"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["overall_decision"] == "UNAVAILABLE"
    assert data["stopping_layer"] == "L7"
    assert data["L1"]["decision"] == "ALLOW"
    assert data["L2"]["decision"] == "ALLOW"

@patch("dashboard_api.services.pipeline_service.AcademiqOrchestrator")
def test_pipeline_malicious_scenario(mock_orchestrator_class):
    mock_instance = mock_orchestrator_class.return_value
    mock_instance.session_id = "test-session"
    mock_instance.process_event.return_value = SecurityDecision(
        decision=DecisionEnum.BLOCK,
        reason_codes=["GCD_POLICY_VIOLATION"],
        risk_score=100.0,
        confidence=1.0,
        source_layers=["L1"],
        related_event_ids=[],
        timestamp_ns=time.time_ns()
    )

    response = client.post("/api/pipeline/run", json={"scenario_id": "L1_GRAMMAR"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["overall_decision"] == "BLOCK"
    assert data["stopping_layer"] == "L1"
    assert data["L1"]["decision"] == "BLOCK"

@patch("dashboard_api.services.pipeline_service.AcademiqOrchestrator")
def test_l4_ensemble_outputs(mock_orchestrator_class):
    mock_instance = mock_orchestrator_class.return_value
    mock_instance.session_id = "test-session"
    mock_instance.process_event.return_value = SecurityDecision(
        decision=DecisionEnum.ALLOW,
        reason_codes=[],
        risk_score=15.0,
        confidence=0.95,
        source_layers=["L1", "L2", "L3", "L4", "L5"],
        related_event_ids=[],
        timestamp_ns=time.time_ns()
    )

    response = client.post("/api/pipeline/run", json={"scenario_id": "L4_BEHAVIORAL"})
    assert response.status_code == 200, response.text
    data = response.json()
    l4 = data["L4"]
    assert l4["isolation_forest_score"] is not None
    assert l4["siamese_score"] is not None
    assert l4["isolation_forest_score"] != l4["siamese_score"]

@patch("dashboard_api.services.pipeline_service.AcademiqOrchestrator")
def test_l5_outputs(mock_orchestrator_class):
    mock_instance = mock_orchestrator_class.return_value
    mock_instance.session_id = "test-session"
    mock_instance.process_event.return_value = SecurityDecision(
        decision=DecisionEnum.ALLOW,
        reason_codes=[],
        risk_score=15.0,
        confidence=0.95,
        source_layers=["L1", "L2", "L3", "L4", "L5"],
        related_event_ids=[],
        timestamp_ns=time.time_ns()
    )

    response = client.post("/api/pipeline/run", json={"scenario_id": "L5_TEMPORAL"})
    assert response.status_code == 200, response.text
    data = response.json()
    l5 = data["L5"]
    assert l5["bayesian_probability"] is not None
    assert l5["governance_state"] == "FREEZE"

def test_eces_sqlite_listing():
    response = client.get("/api/evidence/sessions")
    assert response.status_code == 200, response.text
    data = response.json()
    if data["sessions"]:
        session = data["sessions"][0]
        assert session["execution_mode"] in {ExecutionMode.REAL_RUNTIME.value, ExecutionMode.SIMULATED.value}

def test_eces_sqlite_verification():
    sessions_resp = client.get("/api/evidence/sessions")
    sessions = sessions_resp.json()["sessions"]
    if sessions:
        sess_id = sessions[0]["session_id"]
        resp = client.post(f"/api/evidence/session/{sess_id}/verify")
        assert resp.status_code == 200, resp.text
        verify_data = resp.json()
        assert verify_data["execution_mode"] in {ExecutionMode.REAL_RUNTIME.value, ExecutionMode.SIMULATED.value}
        assert "valid" in verify_data

def test_experiment_results_api():
    response = client.get("/api/experiments")
    assert response.status_code == 200, response.text
    data = response.json()
    assert "experiments" in data
    
    if data["experiments"]:
        exp_id = data["experiments"][0]["experiment_id"]
        detail_resp = client.get(f"/api/experiments/{exp_id}")
        assert detail_resp.status_code == 200, detail_resp.text
        detail_data = detail_resp.json()
        assert "execution_mode" in detail_data

def test_pipeline_invalid_scenario():
    response = client.post("/api/pipeline/run", json={"scenario_id": "NOT_A_REAL_SCENARIO"})
    assert response.status_code == 400
