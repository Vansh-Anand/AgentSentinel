import pytest
import sqlite3
from fastapi.testclient import TestClient
from dashboard_api.main import app

client = TestClient(app)

def test_system_status_api_health():
    # Test A: API status
    response = client.get("/api/system/status")
    assert response.status_code == 200

def test_system_status_schema_contract():
    # Test B: Schema contract
    response = client.get("/api/system/status")
    data = response.json()
    assert "api_version" in data
    assert "backend_status" in data
    assert "database_status" in data
    assert "overall_status" in data
    assert "infrastructure" in data
    assert "layers" in data
    assert "capabilities" in data

def test_system_status_layer_completeness():
    # Test C: Layer completeness
    response = client.get("/api/system/status")
    data = response.json()
    
    layers = {l["layer_id"]: l for l in data["layers"]}
    
    # Check all L1 to L7 are represented
    assert "L1" in layers
    assert "L2" in layers
    assert "L3" in layers
    assert "L4" in layers
    assert "L5" in layers
    assert "L6" in layers
    assert "L7" in layers

def test_system_status_execution_truthfulness():
    # Test D: Execution truthfulness
    response = client.get("/api/system/status")
    data = response.json()
    
    layers = {l["layer_id"]: l for l in data["layers"]}
    l3 = layers["L3"]
    
    # L3 native eBPF must not be falsely reported as active when unavailable
    # The operational status is "PARTIAL", execution_mode "SIMULATED", and limitations mention native eBPF unavailable.
    assert l3["operational_status"] == "PARTIAL"
    assert l3["execution_mode"] == "SIMULATED"
    
    # Also verify L7 isolation is unavailable
    l7 = layers["L7"]
    assert l7["operational_status"] == "UNAVAILABLE"
    assert l7["execution_mode"] == "UNAVAILABLE"

def test_system_status_database_health():
    # Test E: Database status (in a typical test env, the db might exist from other tests, so it should be OPERATIONAL or UNAVAILABLE but not ERROR unless forced)
    response = client.get("/api/system/status")
    data = response.json()
    assert data["database_status"] in ["OPERATIONAL", "UNAVAILABLE"]


def test_eces_status_matches_configured_database(monkeypatch, tmp_path):
    db_path = tmp_path / "eces.db"
    monkeypatch.setenv("AGENTSENTINEL_ECES_DB_PATH", str(db_path))

    missing = client.get("/api/system/status").json()
    assert missing["database_status"] == "UNAVAILABLE"
    assert next(item for item in missing["infrastructure"] if item["name"] == "ECES SQLite Database")["execution_mode"] == "UNAVAILABLE"
    assert next(layer for layer in missing["layers"] if layer["layer_id"] == "L6")["operational_status"] == "UNAVAILABLE"
    assert next(cap for cap in missing["capabilities"] if cap["name"] == "ECES Persistence")["status"] == "Unavailable"

    with sqlite3.connect(db_path) as conn:
        conn.execute("SELECT 1")
    present = client.get("/api/system/status").json()
    assert present["database_status"] == "OPERATIONAL"
    assert next(item for item in present["infrastructure"] if item["name"] == "ECES SQLite Database")["execution_mode"] == "REAL_RUNTIME"
    assert next(layer for layer in present["layers"] if layer["layer_id"] == "L6")["operational_status"] == "OPERATIONAL"
    assert next(cap for cap in present["capabilities"] if cap["name"] == "ECES Persistence")["status"] == "Operational"

def test_system_status_no_fabricated_metrics():
    # Test F: No fabricated metrics (ensure required string fields are non-empty strings and capabilities list is populated)
    response = client.get("/api/system/status")
    data = response.json()
    assert len(data["capabilities"]) > 0
    for cap in data["capabilities"]:
        assert isinstance(cap["name"], str) and len(cap["name"]) > 0
        assert isinstance(cap["status"], str) and len(cap["status"]) > 0
