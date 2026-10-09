from fastapi import APIRouter
from pydantic import BaseModel
import time
import os

router = APIRouter()

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: dict

@router.get("", response_model=HealthResponse)
def get_health():
    # Check component availability
    # Orchestrator is available if we can import it
    orchestrator_ok = False
    try:
        from orchestrator.pipeline.core import AcademiqOrchestrator
        orchestrator_ok = True
    except ImportError:
        pass
        
    # Experiment results available if directory exists
    results_ok = os.path.exists("benchmarks/results")
    
    # ECES SQLite available if DB file exists
    from l6_eces.storage.sqlite_store import DEFAULT_DB_PATH
    eces_ok = os.path.exists(DEFAULT_DB_PATH)
    
    return HealthResponse(
        status="healthy",
        timestamp=str(time.time()),
        components={
            "orchestrator": orchestrator_ok,
            "experiment_results": results_ok,
            "eces_sqlite": eces_ok
        }
    )
