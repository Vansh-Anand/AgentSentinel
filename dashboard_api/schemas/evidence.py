from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from dashboard_api.schemas.common import ExecutionMode

class SessionListItem(BaseModel):
    session_id: str
    event_count: int
    start_time_ns: int
    execution_mode: ExecutionMode

class SessionListResponse(BaseModel):
    sessions: List[SessionListItem]

class ChainRecord(BaseModel):
    sequence_number: int
    timestamp_ns: int
    event_type: str
    source_layer: str
    event_id: str
    previous_hash: str
    event_hash: str
    payload: Dict[str, Any]

class SessionDetailResponse(BaseModel):
    session_id: str
    execution_mode: ExecutionMode
    chain: List[ChainRecord]

class VerifyResponse(BaseModel):
    session_id: str
    valid: bool
    hash_chain_valid: bool = False
    signature_status: str = "NOT_CHECKED"
    records_checked: int
    failure: Optional[str] = None
    execution_mode: ExecutionMode
