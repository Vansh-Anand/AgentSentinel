import pytest
from fastapi.testclient import TestClient
from dashboard_api.main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def isolated_evidence_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSENTINEL_ECES_DB_PATH", str(tmp_path / "eces.db"))

def test_pipeline_to_eces_integration():
    """
    End-to-End Integration Test:
    1. Run a pipeline scenario (which should trigger ECES recording).
    2. Retrieve the session from the ECES evidence list.
    3. Retrieve the full chain details.
    4. Verify the cryptographic chain.
    """
    
    # Step 1: Run pipeline scenario
    payload = {
        "scenario_id": "L7_ATTESTATION"
    }
    
    response = client.post("/api/pipeline/run", json=payload)
    assert response.status_code == 200
    pipeline_result = response.json()
    
    assert pipeline_result["overall_decision"] == "BLOCK"
    session_id = pipeline_result["session_id"]
    
    # Check L6 output explicitly confirms evidence chain
    assert "L6" in pipeline_result
    assert pipeline_result["L6"]["chain_status"] == "APPENDED"
    
    # Step 2: Retrieve the session from ECES
    evidence_resp = client.get("/api/evidence/sessions")
    assert evidence_resp.status_code == 200
    sessions_data = evidence_resp.json()
    
    # Verify our session is in the list
    session_ids = [s["session_id"] for s in sessions_data["sessions"]]
    assert session_id in session_ids
    
    # Step 3: Retrieve chain details
    chain_resp = client.get(f"/api/evidence/session/{session_id}")
    assert chain_resp.status_code == 200
    chain_data = chain_resp.json()
    
    assert chain_data["session_id"] == session_id
    assert len(chain_data["chain"]) > 0
    
    # Step 4: Verify the cryptographic chain via API
    verify_resp = client.post(f"/api/evidence/session/{session_id}/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    
    assert verify_data["session_id"] == session_id
    assert verify_data["valid"] is True
    assert verify_data["records_checked"] >= len(chain_data["chain"])

def test_pipeline_attack_integration():
    """
    Integration Test: 
    Test that an attack scenario is blocked and recorded in ECES correctly.
    """
    payload = {
        "scenario_id": "L2_BACKSLASH"
    }
    
    response = client.post("/api/pipeline/run", json=payload)
    assert response.status_code == 200
    pipeline_result = response.json()
    
    assert pipeline_result["overall_decision"] == "BLOCK"
    
    # Ensure evidence was still recorded despite the block
    session_id = pipeline_result["session_id"]
    verify_resp = client.post(f"/api/evidence/session/{session_id}/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True
