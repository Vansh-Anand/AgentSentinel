from fastapi import APIRouter, HTTPException

from dashboard_api.schemas.pipeline import PipelineRunRequest, PipelineRunResponse
from dashboard_api.services.pipeline_service import PipelineService
from dashboard_api.services.challenge_service import ChallengeRequest, ChallengeResponse, run_challenge

router = APIRouter()
service = PipelineService()


@router.post("/challenge", response_model=ChallengeResponse)
def challenge(request: ChallengeRequest):
    try:
        return run_challenge(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/run", response_model=PipelineRunResponse)
def run_pipeline(request: PipelineRunRequest):
    try:
        return service.run_scenario(request.scenario_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
